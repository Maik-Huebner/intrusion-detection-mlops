"""API tests against a small model trained on synthetic flows (no dataset or MLflow needed)."""

import joblib
import pytest
from fastapi.testclient import TestClient

from ids import schema
from ids.api.schemas import EXAMPLE_FLOW, MAX_BATCH
from ids.drift import build_profile
from ids.io import write_json
from ids.pipeline.train import build_model

PARAMS = {
    "max_iter": 20,
    "learning_rate": 0.1,
    "max_leaf_nodes": 15,
    "l2_regularization": 0.0,
    "random_state": 0,
}


@pytest.fixture
def model_files(prepared_flows, tmp_path, monkeypatch):
    """A model trained on synthetic flows plus the drift profile of its benign training flows."""
    model = build_model(PARAMS).fit(prepared_flows[schema.FEATURES], prepared_flows[schema.TARGET])
    joblib.dump(model, tmp_path / "model.joblib")
    benign = prepared_flows[prepared_flows[schema.TARGET] == 0]
    write_json(tmp_path / "profile.json", build_profile(benign, schema.FEATURES))
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "model.joblib"))
    monkeypatch.setenv("PROFILE_PATH", str(tmp_path / "profile.json"))
    monkeypatch.setenv("THRESHOLD", "0.5")
    monkeypatch.delenv("MODEL_URI", raising=False)
    return tmp_path


@pytest.fixture
def client(model_files):
    from ids.api.app import app

    with TestClient(app) as test_client:
        yield test_client


def flow_from(prepared_flows, row: int) -> dict:
    return {f: float(prepared_flows.loc[row, f]) for f in schema.FEATURES}


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_model_info(client):
    info = client.get("/model").json()
    assert info["source"].endswith("model.joblib")
    assert info["version"] == "file"
    assert info["fallback"] is False
    assert info["threshold"] == 0.5
    assert info["features"] == len(schema.FEATURES)
    assert info["drift_monitoring"] is True


def test_predict_benign_and_attack(client, prepared_flows):
    benign_row = prepared_flows.index[prepared_flows[schema.TARGET] == 0][0]
    attack_row = prepared_flows.index[prepared_flows[schema.TARGET] == 1][0]

    benign = client.post("/predict", json=flow_from(prepared_flows, benign_row)).json()
    attack = client.post("/predict", json=flow_from(prepared_flows, attack_row)).json()

    assert benign["is_attack"] is False
    assert attack["is_attack"] is True
    assert 0 <= benign["attack_probability"] < 0.5 <= attack["attack_probability"] <= 1


def test_docs_example_is_valid(client):
    assert client.post("/predict", json=EXAMPLE_FLOW).status_code == 200


def test_missing_feature_is_rejected(client):
    flow = dict(EXAMPLE_FLOW)
    del flow["Flow Duration"]
    response = client.post("/predict", json=flow)
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "Flow Duration"]


@pytest.mark.parametrize(("feature", "value"), [("Dst Port", 70000), ("Total Fwd Packet", -1)])
def test_out_of_range_values_are_rejected(client, feature, value):
    assert client.post("/predict", json=EXAMPLE_FLOW | {feature: value}).status_code == 422


def test_batch(client, prepared_flows):
    flows = [flow_from(prepared_flows, i) for i in (0, 1, len(prepared_flows) - 1)]
    body = client.post("/predict/batch", json={"flows": flows}).json()
    assert len(body["predictions"]) == 3
    assert body["alarms"] == sum(p["is_attack"] for p in body["predictions"])


def test_batch_limits(client):
    assert client.post("/predict/batch", json={"flows": []}).status_code == 422
    too_many = {"flows": [EXAMPLE_FLOW] * (MAX_BATCH + 1)}
    assert client.post("/predict/batch", json=too_many).status_code == 422


# --- Monitoring -------------------------------------------------------------------------------------


def benign_flows(prepared_flows, shift: bool = False) -> list[dict]:
    benign = prepared_flows[prepared_flows[schema.TARGET] == 0][schema.FEATURES].copy()
    if shift:  # new traffic the model still lets through, but that looks nothing like training
        benign[schema.FEATURES[2:]] = benign[schema.FEATURES[2:]] * 10 + 5000
    return [{f: float(v) for f, v in row.items()} for row in benign.to_dict("records")]


def test_metrics_endpoint(client, prepared_flows):
    client.post("/predict/batch", json={"flows": [flow_from(prepared_flows, i) for i in range(5)]})
    text = client.get("/metrics").text
    assert 'ids_http_requests_total{method="POST",path="/predict/batch",status="200"}' in text
    assert "ids_flows_scored_total" in text
    assert "ids_attack_probability_bucket" in text
    assert 'ids_model_info{fallback="false"' in text


def test_drift_monitor_stays_calm_on_known_traffic(client, prepared_flows):
    assert client.get("/drift").json()["drift"] is None  # window not full yet
    client.post("/predict/batch", json={"flows": benign_flows(prepared_flows)})
    status = client.get("/drift").json()
    assert status["window_flows"] >= 500
    assert status["drift"] is False
    assert "ids_drift_detected 0.0" in client.get("/metrics").text


def test_drift_monitor_detects_shifted_traffic(client, prepared_flows):
    body = client.post("/predict/batch", json={"flows": benign_flows(prepared_flows, shift=True)}).json()
    assert body["alarms"] == 0  # the model is blind to it ...
    status = client.get("/drift").json()
    assert status["drift"] is True  # ... the drift monitor is not
    assert status["drift_share"] > 0.5
    assert "ids_drift_detected 1.0" in client.get("/metrics").text


def test_drift_endpoint_without_profile(model_files, monkeypatch):
    monkeypatch.setenv("PROFILE_PATH", str(model_files / "missing.json"))
    from ids.api.app import app

    with TestClient(app) as test_client:
        assert test_client.get("/model").json()["drift_monitoring"] is False
        assert test_client.get("/drift").status_code == 404
        assert test_client.post("/predict", json=EXAMPLE_FLOW).status_code == 200


def test_unreachable_registry_falls_back_to_baked_in_model(model_files, monkeypatch):
    pytest.importorskip("mlflow")
    monkeypatch.setenv("MLFLOW_TRACKING_URI", f"sqlite:///{model_files / 'empty.db'}")
    monkeypatch.setenv("MODEL_URI", "models:/ids-detector@champion")
    from ids.api.app import app

    with TestClient(app) as test_client:
        info = test_client.get("/model").json()
        assert info["fallback"] is True
        assert info["version"] == "file"
        assert test_client.post("/predict", json=EXAMPLE_FLOW).status_code == 200
