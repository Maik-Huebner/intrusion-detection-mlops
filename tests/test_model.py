import numpy as np

from ids import schema
from ids.pipeline.train import build_model
from ids.quality_gate import evaluate_gate

PARAMS = {
    "max_iter": 20,
    "learning_rate": 0.1,
    "max_leaf_nodes": 15,
    "l2_regularization": 0.0,
    "random_state": 0,
}
THRESHOLDS = {"min_detection_rate": 0.9, "max_false_alarm_rate": 0.05, "min_f1": 0.9}


def test_model_learns_separable_attacks(prepared_flows):
    model = build_model(PARAMS).fit(prepared_flows[schema.FEATURES], prepared_flows[schema.TARGET])
    assert model.score(prepared_flows[schema.FEATURES], prepared_flows[schema.TARGET]) > 0.95


def test_training_is_deterministic(prepared_flows):
    x, y = prepared_flows[schema.FEATURES], prepared_flows[schema.TARGET]
    a = build_model(PARAMS).fit(x, y).predict_proba(x)
    b = build_model(PARAMS).fit(x, y).predict_proba(x)
    np.testing.assert_array_equal(a, b)


def test_quality_gate_passes_good_model():
    passed, _ = evaluate_gate({"detection_rate": 0.99, "false_alarm_rate": 0.001, "f1": 0.99}, THRESHOLDS)
    assert passed


def test_quality_gate_blocks_noisy_model():
    passed, rows = evaluate_gate({"detection_rate": 0.99, "false_alarm_rate": 0.2, "f1": 0.95}, THRESHOLDS)
    assert not passed
    assert [r[0] for r in rows if not r[3]] == ["false_alarm_rate"]


def test_quality_gate_blocks_undefined_metric():
    passed, _ = evaluate_gate({"detection_rate": None, "false_alarm_rate": 0.0, "f1": None}, THRESHOLDS)
    assert not passed
