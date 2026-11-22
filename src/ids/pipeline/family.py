"""Stage ``family``: *which* attack is it? A second model for the flows the detector flags.

The detector answers "attack or not". For an analyst the next question is "what kind?". This stage
trains a multi-class model on the attack flows of the training days to predict the attack type
(e.g. ``SSH-Patator``, ``DoS Hulk``); the family follows from the type (``schema.attack_category``).

A classifier can only name types it has seen. Faced with a new attack it still picks one of them,
often confidently. The report shows that on purpose: what does the model call Thursday's and
Friday's unseen attacks? Below ``min_confidence`` the API reports the type as uncertain instead of
naming a family it would just be guessing.

Outputs: ``models/family.joblib``, ``reports/family.json``.
"""

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from ids import schema
from ids.config import FAMILY_MODEL_FILE, PREPARED_DIR, REPORTS_DIR, load_params
from ids.io import write_json

UNCERTAIN = "uncertain"


def build_family_model(params: dict) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        max_iter=params["max_iter"],
        learning_rate=params["learning_rate"],
        max_leaf_nodes=params["max_leaf_nodes"],
        class_weight="balanced",  # Heartbleed has a handful of flows, DoS Hulk over 100,000
        early_stopping=False,  # deterministic, see train.py
        random_state=params["random_state"],
    )


def predict_types(model, df: pd.DataFrame, min_confidence: float) -> tuple[np.ndarray, np.ndarray]:
    """Attack type per flow (``uncertain`` below ``min_confidence``) and the confidence."""
    probabilities = model.predict_proba(df[schema.FEATURES])
    confidence = probabilities.max(axis=1)
    types = model.classes_[probabilities.argmax(axis=1)].astype(object)
    types[confidence < min_confidence] = UNCERTAIN
    return types, confidence


def family_of(attack_type: str) -> str:
    return UNCERTAIN if attack_type == UNCERTAIN else schema.attack_category(attack_type)


def _share(counts: pd.Series) -> dict:
    return {k: round(float(v), 4) for k, v in (counts / counts.sum()).items()}


def main() -> None:
    params = load_params("family")
    train = pd.read_parquet(PREPARED_DIR / "train.parquet")
    attacks = train[train[schema.TARGET] == 1]
    model = build_family_model(params).fit(attacks[schema.FEATURES], attacks[schema.LABEL])
    FAMILY_MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, FAMILY_MODEL_FILE)

    report = {"known_types": sorted(model.classes_.tolist()), "min_confidence": params["min_confidence"]}
    test = pd.read_parquet(PREPARED_DIR / "test.parquet")
    test_attacks = test[test[schema.TARGET] == 1]
    types, _ = predict_types(model, test_attacks, params["min_confidence"])
    families = np.array([family_of(t) for t in types])
    report["test"] = {
        "attacks": len(test_attacks),
        "type_accuracy": round(float((types == test_attacks[schema.LABEL].to_numpy()).mean()), 4),
        "family_accuracy": round(float((families == test_attacks[schema.CATEGORY].to_numpy()).mean()), 4),
        "uncertain": round(float((types == UNCERTAIN).mean()), 4),
    }

    # What does the model call attack families it has never seen?
    future = pd.read_parquet(PREPARED_DIR / "future.parquet")
    future_attacks = future[future[schema.TARGET] == 1]
    report["future_by_true_family"] = {}
    if len(future_attacks):
        types, _ = predict_types(model, future_attacks, params["min_confidence"])
        predicted = pd.Series([family_of(t) for t in types], index=future_attacks.index)
        for family, idx in future_attacks.groupby(schema.CATEGORY).groups.items():
            report["future_by_true_family"][family] = {
                "attacks": len(idx),
                "predicted_family_share": _share(predicted.loc[idx].value_counts()),
            }

    write_json(REPORTS_DIR / "family.json", report)
    print(f"known types: {', '.join(report['known_types'])}")
    print(f"test: {report['test']}")
    for family, v in report["future_by_true_family"].items():
        print(f"unseen {family:<13} -> {v['predicted_family_share']}")


if __name__ == "__main__":
    main()
