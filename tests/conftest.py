"""Shared fixtures: small synthetic flows that follow the real raw-data schema.

Unit tests must not depend on the 328 MB dataset, so CI can run them in seconds on every push.
"""

import numpy as np
import pandas as pd
import pytest

from ids import schema


def make_raw(n_benign: int = 600, n_attack: int = 600, seed: int = 0) -> pd.DataFrame:
    """Raw flows as they appear in the CIC-IDS2017 CSVs.

    Attacks are separable on purpose (short flows, many SYNs), so a model can learn them.
    """
    rng = np.random.default_rng(seed)
    n = n_benign + n_attack
    is_attack = np.r_[np.zeros(n_benign, dtype=bool), np.ones(n_attack, dtype=bool)]

    df = pd.DataFrame(rng.uniform(0, 1000, size=(n, len(schema.FEATURES))), columns=schema.FEATURES)
    df["Protocol"] = 6
    df["Dst Port"] = np.where(is_attack, 80, rng.integers(1, 65535, n))
    df["Flow Duration"] = np.where(is_attack, rng.uniform(0, 50, n), rng.uniform(1e4, 1e6, n))
    df["SYN Flag Count"] = np.where(is_attack, rng.integers(5, 20, n), rng.integers(0, 2, n))

    df.insert(0, "id", np.arange(n))
    df.insert(1, "Flow ID", "10.0.0.1-10.0.0.2-1234-80-6")
    df.insert(2, "Src IP", "10.0.0.1")
    df.insert(3, "Src Port", 1234)
    df.insert(4, "Dst IP", "10.0.0.2")
    df.insert(7, "Timestamp", "2017-07-05 10:00:00")
    df[schema.RAW_LABEL] = np.where(is_attack, "DoS Hulk", schema.BENIGN)
    df[schema.RAW_ATTEMPTED] = -1
    return df


@pytest.fixture
def raw_flows() -> pd.DataFrame:
    return make_raw()


@pytest.fixture
def prepared_flows(raw_flows) -> pd.DataFrame:
    from ids.pipeline.prepare import prepare_day

    df, _ = prepare_day(raw_flows, "wednesday")
    return df
