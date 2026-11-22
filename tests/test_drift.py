import json

import numpy as np
import pandas as pd
import pytest

from ids import schema
from ids.drift import build_profile, psi, summarize


@pytest.fixture
def benign(prepared_flows) -> pd.DataFrame:
    return prepared_flows[prepared_flows[schema.TARGET] == 0]


def test_profile_is_json_and_deterministic(benign):
    a = build_profile(benign, schema.FEATURES)
    b = build_profile(benign, schema.FEATURES)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["rows"] == len(benign)
    for ref in a["features"].values():
        assert len(ref["shares"]) == len(ref["edges"]) + 1
        assert sum(ref["shares"]) == pytest.approx(1, abs=1e-5)


def test_same_distribution_has_no_drift(benign):
    profile = build_profile(benign, schema.FEATURES)
    psis = psi(profile, benign)
    assert max(psis.values()) == pytest.approx(0, abs=1e-6)
    assert summarize(psis, 0.2, 0.1)["drift"] is False


def test_shifted_traffic_drifts(benign):
    profile = build_profile(benign, schema.FEATURES)
    shifted = benign.copy()
    shifted[schema.FEATURES[2:]] = shifted[schema.FEATURES[2:]] * 10 + 5000  # all but port and protocol
    summary = summarize(psi(profile, shifted), 0.2, 0.1)
    assert summary["drift"] is True
    assert summary["drifted_features"] > len(schema.FEATURES) // 2
    assert len(summary["top_features"]) == 10


def test_constant_feature_never_drifts(benign):
    """Protocol is always 6 in the fixture: one bin, PSI 0, even for other values."""
    profile = build_profile(benign, ["Protocol"])
    assert psi(profile, benign.assign(Protocol=6))["Protocol"] == pytest.approx(0, abs=1e-6)


def test_psi_grows_with_the_shift(benign):
    profile = build_profile(benign, ["Flow Duration"])
    values = [
        psi(profile, benign.assign(**{"Flow Duration": benign["Flow Duration"] * f}))["Flow Duration"]
        for f in (1.0, 1.5, 3.0)
    ]
    assert values == sorted(values)
    assert values[0] < 0.01 < values[-1]


def test_summarize_threshold_is_strict():
    psis = {"a": 0.3, "b": 0.0, "c": 0.0, "d": 0.0}
    assert summarize(psis, 0.2, 0.25)["drift"] is False  # exactly 25 % is not more than 25 %
    assert summarize(psis, 0.2, 0.2)["drift"] is True
    assert summarize({}, 0.2, 0.1) == {
        "drift": False,
        "drifted_features": 0,
        "drift_share": 0.0,
        "top_features": {},
    }


def test_empty_frame_does_not_crash(benign):
    profile = build_profile(benign, schema.FEATURES)
    assert all(np.isfinite(list(psi(profile, benign.iloc[:0]).values())))
