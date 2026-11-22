"""Data drift without labels: do today's flows still look like the training data?

Labels arrive late in a SOC (an analyst has to confirm an incident first), and a model that has never
seen an attack type is often *confidently* wrong, so its own output stays calm. The input data does
not lie, though: new attack traffic changes the distribution of the flow features.

Method: Population Stability Index (PSI) per feature.

1. ``build_profile`` cuts every feature of the training data into (up to) ten quantile bins and stores
   the bin edges and the share of training flows per bin. This *reference profile* belongs to a
   model version and is shipped with it.
2. ``psi`` sorts new flows into the same bins and compares the shares:
   ``PSI = sum((new - ref) * ln(new / ref))``. Rule of thumb: < 0.1 stable, 0.1-0.25 moderate,
   > 0.25 strong shift.
3. ``summarize``: the data set drifts when the share of drifted features exceeds a threshold.

The same functions run offline in the DVC stage ``drift`` and online in the API over a sliding window.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

QUANTILES = np.linspace(0.1, 0.9, 9)
EPSILON = 1e-4  # empty bins would make the logarithm explode


def _bin_shares(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    counts = np.bincount(np.searchsorted(edges, values, side="right"), minlength=len(edges) + 1)
    return counts / max(len(values), 1)


def build_profile(df: pd.DataFrame, features: list[str]) -> dict:
    """Quantile bin edges and reference shares per feature."""
    profile = {}
    for feature in features:
        values = df[feature].to_numpy(dtype=np.float64)
        # method="lower" picks real data values: no interpolation, identical on every platform
        edges = np.unique(np.quantile(values, QUANTILES, method="lower"))
        profile[feature] = {
            "edges": [float(e) for e in edges],
            "shares": [round(float(s), 6) for s in _bin_shares(values, edges)],
        }
    return {"rows": len(df), "features": profile}


def psi(profile: dict, df: pd.DataFrame) -> dict[str, float]:
    """PSI of every profiled feature between the reference and ``df``."""
    result = {}
    for feature, ref in profile["features"].items():
        expected = np.clip(np.asarray(ref["shares"]), EPSILON, None)
        actual = np.clip(
            _bin_shares(df[feature].to_numpy(dtype=np.float64), np.asarray(ref["edges"])), EPSILON, None
        )
        result[feature] = float(np.sum((actual - expected) * np.log(actual / expected)))
    return result


def summarize(
    psis: dict[str, float], feature_threshold: float, share_threshold: float, top: int = 10
) -> dict:
    """Which features drift, and does the data set as a whole drift?"""
    drifted = sorted((f for f, v in psis.items() if v > feature_threshold), key=lambda f: -psis[f])
    share = len(drifted) / len(psis) if psis else 0.0
    return {
        "drift": share > share_threshold,
        "drifted_features": len(drifted),
        "drift_share": round(share, 4),
        "top_features": {f: round(psis[f], 4) for f in sorted(psis, key=lambda f: -psis[f])[:top]},
    }


def unusual_features(profile: dict, flow: dict, top: int = 5) -> list[dict]:
    """The features of one flow that lie furthest outside the benign 10-90 % range.

    Gives an analyst (and the LLM note) something concrete to look at: "Flow Duration 2 ms,
    normally 1.3 s - 98 s". Distance is measured in multiples of the benign range's width.
    """
    found = []
    for feature, ref in profile["features"].items():
        edges = ref["edges"]
        if not edges or feature not in flow:
            continue
        low, high, value = edges[0], edges[-1], float(flow[feature])
        if low <= value <= high:
            continue
        width = (high - low) or (abs(high) or 1.0)
        distance = (low - value if value < low else value - high) / width
        found.append({"feature": feature, "value": value, "normal_low": low, "normal_high": high,
                      "distance": round(distance, 3)})  # fmt: skip
    return sorted(found, key=lambda f: -f["distance"])[:top]
