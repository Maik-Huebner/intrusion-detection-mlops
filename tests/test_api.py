"""API tests against a small model trained on synthetic flows (no dataset or MLflow needed)."""

import joblib
import pytest
from fastapi.testclient import TestClient

from ids import schema
from ids.api.schemas import EXAMPLE_FLOW, MAX_BATCH
from ids.drift import build_profile
from ids.io import write_json
from ids.pipeline.family import build_family_model
from ids.pipeline.train import build_model

PARAMS = {
    "max_iter": 20,
    "learning_rate": 0.1,
    "max_leaf_nodes": 15,
    "l2_regularization": 0.0,
    "random_state": 0,
}


def two_attack_types(flows):
    """The fixture only has 'DoS Hulk'; relabel half of the attacks as SSH-Patator on port 22."""
    attacks = flows[flows[schema.TARGET] == 1].copy()
    ssh = attacks.index[::2]
    attacks.loc[ssh, "Dst Port"] = 22
    attacks.loc[ssh, schema.LABEL] = "SSH-Patator"
    return attacks


@pytest.fixture
def model_files(prepared_flows, tmp_path, monkeypatch):
    """A model trained on synthetic flows plus the drift profile of its benign training flows."""
    model = build_model(PARAMS).fit(prepared_flows[schema.FEATURES], prepared_flows[schema.TARGET])
    joblib.dump(model, tmp_path / "model.joblib")
    benign = prepared_flows[prepared_flows[schema.TARGET] == 0]
    write_json(tmp_path / "profile.json", build_profile(benign, schema.FEATURES))
    attacks = two_attack_types(prepared_flows)
    family = build_family_model(PARAMS).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    joblib.dump(family, tmp_path / "family.joblib")
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "model.joblib"))
    monkeypatch.setenv("PROFILE_PATH", str(tmp_path / "profile.json"))
    monkeypatch.setenv("FAMILY_PATH", str(tmp_path / "family.joblib"))
    for var in ("LLM_BASE_URL", "LLM_PROVIDER", "ANTHROPIC_API_KEY", "REVISION"):
        monkeypatch.delenv(var, raising=False)  # tests never call a real LLM
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


# --- Attack type and analyst note -----------------------------------------------------------------


def attack_and_benign(prepared_flows) -> tuple[dict, dict]:
    attack_row = prepared_flows.index[prepared_flows[schema.TARGET] == 1][1]
    benign_row = prepared_flows.index[prepared_flows[schema.TARGET] == 0][0]
    return flow_from(prepared_flows, attack_row), flow_from(prepared_flows, benign_row)


def test_alarms_get_an_attack_type(client, prepared_flows):
    attack, benign = attack_and_benign(prepared_flows)
    alarm = client.post("/predict", json=attack).json()
    assert alarm["attack_type"] == "DoS Hulk"
    assert alarm["family"] == "DoS"
    assert alarm["type_confidence"] >= 0.9
    quiet = client.post("/predict", json=benign).json()
    assert quiet["attack_type"] is None and quiet["family"] is None
    assert 'ids_alarms_by_family_total{family="DoS"}' in client.get("/metrics").text


def test_explain_benign_flow_needs_no_llm(client, prepared_flows, monkeypatch):
    from ids.api import llm

    monkeypatch.setattr(llm, "generate", lambda ctx: pytest.fail("LLM must not be called for benign flows"))
    body = client.post("/explain", json=attack_and_benign(prepared_flows)[1]).json()
    assert body["source"] == "no_alarm"
    assert body["note"].startswith("Kein Alarm")


def test_explain_without_llm_uses_the_template(client, prepared_flows):
    body = client.post("/explain", json=attack_and_benign(prepared_flows)[0]).json()
    assert body["source"] == "fallback"
    assert body["reason"] == "not_configured"
    assert "DoS Hulk" in body["note"]
    assert body["unusual_features"]  # the attack flow lies outside the benign ranges


def fake_llm(monkeypatch, answer=None, error=None):
    from ids.api import llm

    monkeypatch.setenv("LLM_BASE_URL", "http://llm.invalid/v1")

    def generate(ctx):
        if error:
            raise error
        return {"text": answer, "llm_model": "fake", "prompt_version": "v2", "tokens": 42, "seconds": 0.1}

    monkeypatch.setattr(llm, "generate", generate)


def test_explain_with_a_good_llm_note(client, prepared_flows, monkeypatch):
    note = "Erkannt wurde DoS Hulk, sehr wahrscheinlich. Auffällig ist die kurze Flow Duration. Ziel prüfen."
    fake_llm(monkeypatch, answer=note)
    body = client.post("/explain", json=attack_and_benign(prepared_flows)[0]).json()
    assert body["source"] == "llm"
    assert body["note"] == note
    assert all(body["rules"].values())
    assert 'ids_llm_requests_total{result="ok"}' in client.get("/metrics").text


def test_explain_rejects_a_hallucinating_note(client, prepared_flows, monkeypatch):
    fake_llm(monkeypatch, answer="DoS Hulk von 10.0.0.5, vermutlich ein Botnet (CVE-2014-0160).")
    body = client.post("/explain", json=attack_and_benign(prepared_flows)[0]).json()
    assert body["source"] == "fallback"
    assert body["reason"] == "rules"
    assert body["rules"]["no_invented_identifiers"] is False
    assert body["rules"]["no_other_attack_family"] is False
    assert "10.0.0.5" not in body["note"]


def test_explain_survives_an_llm_outage(client, prepared_flows, monkeypatch):
    fake_llm(monkeypatch, error=TimeoutError("LLM too slow"))
    response = client.post("/explain", json=attack_and_benign(prepared_flows)[0])
    assert response.status_code == 200
    assert response.json()["reason"] == "TimeoutError"
    assert 'ids_llm_errors_total{kind="TimeoutError"}' in client.get("/metrics").text


def test_explain_over_budget_uses_the_template(model_files, prepared_flows, monkeypatch):
    fake_llm(monkeypatch, answer="DoS Hulk erkannt. Viele Pakete. Webserver prüfen.")
    monkeypatch.setenv("LLM_MAX_PER_MINUTE", "1")
    from ids.api.app import app

    with TestClient(app) as c:
        flow = attack_and_benign(prepared_flows)[0]
        assert c.post("/explain", json=flow).json()["reason"] != "budget"
        body = c.post("/explain", json=flow).json()
        assert body["source"] == "fallback" and body["reason"] == "budget"
        assert 'ids_llm_requests_total{result="budget"}' in c.get("/metrics").text


def test_nan_and_infinity_are_rejected(client, prepared_flows):
    flow = attack_and_benign(prepared_flows)[0]
    for bad in ("NaN", "Infinity"):
        body = (
            f'{{"Flow Bytes/s": {bad}, '
            + ", ".join(f'"{k}": {v}' for k, v in flow.items() if k != "Flow Bytes/s")
            + "}"
        )
        response = client.post("/predict", content=body, headers={"Content-Type": "application/json"})
        assert response.status_code == 422


def test_model_info_shows_the_revision(model_files, monkeypatch):
    monkeypatch.setenv("REVISION", "abc1234")
    from ids.api.app import app

    with TestClient(app) as c:
        assert c.get("/model").json()["revision"] == "abc1234"
