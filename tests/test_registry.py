"""Champion/challenger logic of the model registry, against a throwaway MLflow store in tmp_path."""

from pathlib import Path

import joblib
import numpy as np
import pytest
import yaml

pytest.importorskip("mlflow")

from ids import registry, schema  # noqa: E402
from ids.io import write_json  # noqa: E402
from ids.pipeline.train import build_model  # noqa: E402

PARAMS = {
    "split": {"train_days": ["monday"], "future_days": [], "test_size": 0.2, "random_state": 0},
    "train": {"max_iter": 20, "learning_rate": 0.1, "max_leaf_nodes": 15, "l2_regularization": 0.0,
              "random_state": 0},
    "evaluate": {"threshold": 0.5},
    "quality_gate": {"min_detection_rate": 0.9, "max_false_alarm_rate": 0.05, "min_f1": 0.9},
}  # fmt: skip
GOOD_METRICS = {"test": {"detection_rate": 1.0, "false_alarm_rate": 0.0, "f1": 1.0}}


@pytest.fixture
def project(tmp_path, monkeypatch, prepared_flows):
    """A minimal project directory: params, metrics, test data and an MLflow store."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MLFLOW_TRACKING_URI", f"sqlite:///{tmp_path / 'mlflow.db'}")
    monkeypatch.delenv("MLFLOW_ALLOW_PICKLE_DESERIALIZATION", raising=False)
    (tmp_path / "params.yaml").write_text(yaml.safe_dump(PARAMS))
    (tmp_path / "dvc.lock").write_text(yaml.safe_dump({"stages": {}}))
    (tmp_path / "reports").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "data/prepared").mkdir(parents=True)
    prepared_flows.to_parquet(tmp_path / "data/prepared/test.parquet")
    return prepared_flows


def _register(flows, *, shuffle_labels: bool, metrics: dict = GOOD_METRICS) -> str:
    """Train a model (useless if the labels are shuffled), write its metrics and register it."""
    y = flows[schema.TARGET].to_numpy()
    if shuffle_labels:
        y = np.random.default_rng(0).permutation(y)
    model = build_model(PARAMS["train"]).fit(flows[schema.FEATURES], y)
    joblib.dump(model, "models/model.joblib")
    write_json(Path("metrics.json"), metrics)
    return registry.log_run()


def _champion() -> str:
    client = registry._client()
    return str(client.get_model_version_by_alias(registry.MODEL_NAME, registry.CHAMPION).version)


def test_first_model_becomes_champion(project):
    _register(project, shuffle_labels=False)
    registry.promote()
    assert _champion() == "1"


def test_better_challenger_replaces_champion_and_rollback_works(project):
    _register(project, shuffle_labels=True)  # v1: a weak model that is champion only because it is first
    registry.promote()
    _register(project, shuffle_labels=False)  # v2: clearly better on the same recent data
    registry.promote()
    assert _champion() == "2"

    registry.set_champion("1")  # rollback
    assert _champion() == "1"


def test_worse_challenger_keeps_champion(project):
    _register(project, shuffle_labels=False)
    registry.promote()
    _register(project, shuffle_labels=True)
    registry.promote()
    assert _champion() == "1"


def test_challenger_failing_the_quality_gate_is_not_promoted(project):
    _register(project, shuffle_labels=True)
    registry.promote()
    bad = {"test": {"detection_rate": 0.5, "false_alarm_rate": 0.0, "f1": 0.6}}
    _register(project, shuffle_labels=False, metrics=bad)
    registry.promote()
    assert _champion() == "1"


def test_registered_model_round_trip(project):
    """skops serialisation: the registered model predicts exactly like the trained one."""
    _register(project, shuffle_labels=False)
    registry.promote()
    original = joblib.load("models/model.joblib").predict_proba(project[schema.FEATURES])
    loaded = registry.load_registered_model(f"models:/{registry.MODEL_NAME}@{registry.CHAMPION}")
    np.testing.assert_array_equal(loaded.predict_proba(project[schema.FEATURES]), original)


def test_serving_bundle_carries_profile_and_attack_type_model(project):
    """One registry version = detector + drift profile + attack type model, loaded together."""
    from ids.drift import build_profile
    from ids.pipeline.family import build_family_model

    attacks = project[project[schema.TARGET] == 1].copy()
    attacks.loc[attacks.index[::2], schema.LABEL] = "SSH-Patator"
    attacks.loc[attacks.index[::2], "Dst Port"] = 22
    family = build_family_model(PARAMS["train"]).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    joblib.dump(family, "models/family.joblib")
    write_json(Path("models/reference_profile.json"), build_profile(project, schema.FEATURES))
    _register(project, shuffle_labels=False)
    registry.promote()

    bundle = registry.load_serving_bundle(f"models:/{registry.MODEL_NAME}@{registry.CHAMPION}")
    assert bundle["version"] == "1"
    assert set(bundle["profile"]["features"]) == set(schema.FEATURES)
    np.testing.assert_array_equal(
        bundle["family_model"].predict_proba(attacks[schema.FEATURES]),
        family.predict_proba(attacks[schema.FEATURES]),
    )
