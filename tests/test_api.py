"""API tests against a small model trained on synthetic flows (no dataset or MLflow needed)."""

import joblib
import pytest
from fastapi.testclient import TestClient

from ids import schema
from ids.api.schemas import EXAMPLE_FLOW, MAX_BATCH
from ids.pipeline.train import build_model

PARAMS = {
    "max_iter": 20,
    "learning_rate": 0.1,
    "max_leaf_nodes": 15,
    "l2_regularization": 0.0,
    "random_state": 0,
}


@pytest.fixture
def client(prepared_flows, tmp_path, monkeypatch):
    model = build_model(PARAMS).fit(prepared_flows[schema.FEATURES], prepared_flows[schema.TARGET])
    path = tmp_path / "model.joblib"
    joblib.dump(model, path)
    monkeypatch.setenv("MODEL_PATH", str(path))
    monkeypatch.setenv("THRESHOLD", "0.5")
    monkeypatch.delenv("MODEL_URI", raising=False)

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
    assert info["threshold"] == 0.5
    assert info["features"] == len(schema.FEATURES)


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
