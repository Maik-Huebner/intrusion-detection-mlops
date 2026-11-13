import numpy as np
import pytest

from ids import schema
from ids.pipeline.prepare import prepare_day


def test_identifier_columns_are_dropped(prepared_flows):
    assert not set(schema.ID_COLUMNS) & set(prepared_flows.columns)
    assert list(prepared_flows.columns[: len(schema.FEATURES)]) == schema.FEATURES


def test_attempted_flows_become_benign(raw_flows):
    raw_flows.loc[:9, schema.RAW_LABEL] = "DoS Hulk - Attempted"
    raw_flows.loc[:9, schema.RAW_ATTEMPTED] = 2

    df, stats = prepare_day(raw_flows, "wednesday")

    assert stats["attempted_relabelled_benign"] == 10
    assert (df.loc[:9, schema.LABEL] == schema.BENIGN).all()
    assert (df.loc[:9, schema.TARGET] == 0).all()


def test_rows_with_infinite_or_missing_values_are_dropped(raw_flows):
    raw_flows.loc[0, "Flow Bytes/s"] = np.inf
    raw_flows.loc[1, "Flow Packets/s"] = np.nan

    df, stats = prepare_day(raw_flows, "wednesday")

    assert stats["dropped_non_finite"] == 2
    assert len(df) == len(raw_flows) - 2
    assert np.isfinite(df[schema.FEATURES].to_numpy()).all()


def test_header_length_overflow_rows_are_dropped(raw_flows):
    raw_flows.loc[0, "Fwd Header Length"] = -32544
    raw_flows.loc[1, "Bwd Header Length"] = -12

    df, stats = prepare_day(raw_flows, "wednesday")

    assert stats["dropped_header_overflow"] == 2
    assert (df[schema.OVERFLOW_FEATURES] >= 0).all().all()


def test_target_category_and_dtypes(prepared_flows):
    assert set(prepared_flows[schema.TARGET]) == {0, 1}
    assert set(prepared_flows[schema.CATEGORY]) == {"Benign", "DoS"}
    assert (prepared_flows[schema.FEATURES].dtypes == "float32").all()
    assert (prepared_flows[schema.DAY] == "wednesday").all()


def test_missing_raw_column_raises(raw_flows):
    with pytest.raises(ValueError, match="missing columns"):
        prepare_day(raw_flows.drop(columns="Flow Duration"), "monday")
