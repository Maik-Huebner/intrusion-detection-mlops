import pytest

from ids import schema


def test_features_are_unique_and_exclude_identifiers():
    assert len(schema.FEATURES) == len(set(schema.FEATURES))
    assert not set(schema.FEATURES) & set(schema.ID_COLUMNS)
    assert schema.RAW_LABEL not in schema.FEATURES


def test_counter_features_are_a_subset_of_features():
    assert schema.COUNTER_FEATURES
    assert set(schema.COUNTER_FEATURES) <= set(schema.FEATURES)


@pytest.mark.parametrize(
    ("label", "category"),
    [
        ("BENIGN", "Benign"),
        ("FTP-Patator", "Brute Force"),
        ("SSH-Patator", "Brute Force"),
        ("DoS Hulk", "DoS"),
        ("DoS Slowloris", "DoS"),
        ("DDoS", "DDoS"),
        ("Heartbleed", "Heartbleed"),
        ("Web Attack - XSS", "Web Attack"),
        ("Web Attack - SQL Injection", "Web Attack"),
        ("Infiltration", "Infiltration"),
        ("Infiltration - Portscan", "Infiltration"),
        ("Botnet", "Botnet"),
        ("Portscan", "PortScan"),
        ("Something new", "Unknown"),
    ],
)
def test_attack_category(label, category):
    assert schema.attack_category(label) == category
