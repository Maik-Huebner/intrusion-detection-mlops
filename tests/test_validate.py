import pytest

from ids import schema
from ids.pipeline.validate import validate_frame


def test_clean_data_passes(prepared_flows):
    assert validate_frame(prepared_flows) == []


def test_missing_column_is_reported(prepared_flows):
    errors = validate_frame(prepared_flows.drop(columns="Protocol"))
    assert errors == ["missing columns: ['Protocol']"]


def test_too_few_rows(prepared_flows):
    assert any("too few rows" in e for e in validate_frame(prepared_flows.head(10)))


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("Flow Duration", float("nan"), "missing feature values"),
        ("Total Fwd Packet", -1.0, "negative packet/byte/flag counters"),
        ("Protocol", 99.0, "unknown protocols"),
        ("Dst Port", 70000.0, "destination port outside"),
    ],
)
def test_broken_feature_values_are_reported(prepared_flows, column, value, message):
    prepared_flows.loc[0, column] = value
    assert any(message in e for e in validate_frame(prepared_flows))


def test_unknown_label_is_reported(prepared_flows):
    prepared_flows.loc[0, schema.LABEL] = "Zero Day"
    prepared_flows.loc[0, schema.CATEGORY] = schema.attack_category("Zero Day")
    assert any("unknown labels" in e for e in validate_frame(prepared_flows))


def test_leftover_attempted_label_is_reported(prepared_flows):
    prepared_flows.loc[0, schema.LABEL] = "DoS Hulk - Attempted"
    assert any("Attempted" in e for e in validate_frame(prepared_flows))


def test_target_must_match_label(prepared_flows):
    benign_row = prepared_flows.index[prepared_flows[schema.LABEL] == schema.BENIGN][0]
    prepared_flows.loc[benign_row, schema.TARGET] = 1
    assert any("target does not match label" in e for e in validate_frame(prepared_flows))
