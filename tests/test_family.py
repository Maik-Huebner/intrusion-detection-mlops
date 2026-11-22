import numpy as np

from ids import schema
from ids.pipeline.family import UNCERTAIN, build_family_model, family_of, predict_types

PARAMS = {"max_iter": 20, "learning_rate": 0.1, "max_leaf_nodes": 15, "random_state": 0}


def labelled_attacks(prepared_flows):
    attacks = prepared_flows[prepared_flows[schema.TARGET] == 1].copy()
    ssh = attacks.index[::2]
    attacks.loc[ssh, "Dst Port"] = 22
    attacks.loc[ssh, schema.LABEL] = "SSH-Patator"
    return attacks


def test_family_model_learns_attack_types(prepared_flows):
    attacks = labelled_attacks(prepared_flows)
    model = build_family_model(PARAMS).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    types, confidence = predict_types(model, attacks, min_confidence=0.5)
    assert (types == attacks[schema.LABEL].to_numpy()).mean() > 0.95
    assert ((confidence >= 0) & (confidence <= 1)).all()


def test_low_confidence_becomes_uncertain(prepared_flows):
    attacks = labelled_attacks(prepared_flows)
    model = build_family_model(PARAMS).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    types, _ = predict_types(model, attacks, min_confidence=1.01)  # nothing is that sure
    assert set(types) == {UNCERTAIN}


def test_family_model_is_deterministic(prepared_flows):
    attacks = labelled_attacks(prepared_flows)
    a = build_family_model(PARAMS).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    b = build_family_model(PARAMS).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    np.testing.assert_array_equal(
        a.predict_proba(attacks[schema.FEATURES]), b.predict_proba(attacks[schema.FEATURES])
    )


def test_family_of():
    assert family_of("SSH-Patator") == "Brute Force"
    assert family_of("DoS Hulk") == "DoS"
    assert family_of(UNCERTAIN) == UNCERTAIN
