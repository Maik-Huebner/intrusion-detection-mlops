"""Stage ``drift``: would the monitoring have noticed the new attacks - without labels?

1. Build the reference profile from the *benign* training flows (``models/reference_profile.json``).
   It is versioned with the model and shipped with it: the API compares live traffic against it.
2. For the test set and every future day, take the flows the model lets through as benign and
   compute the PSI per feature against the profile (see ``ids.drift``).

Why only the "let through" flows? Attacks the model recognises are already alarms. The danger is the
attack that looks benign to the model - it changes what "benign" traffic looks like. Watching only
these flows keeps normal traffic at zero drift, whatever the mix of known attacks.

Labels are *not* used for the drift decision. ``hidden_attacks`` is reported only to explain it.

Outputs: ``models/reference_profile.json``, ``reports/drift.json``.
"""

import joblib
import pandas as pd

from ids import schema
from ids.config import MODEL_FILE, PREPARED_DIR, REFERENCE_PROFILE, REPORTS_DIR, load_params
from ids.drift import build_profile, psi, summarize
from ids.io import write_json


def main() -> None:
    params = load_params("drift")
    threshold = load_params("evaluate")["threshold"]
    model = joblib.load(MODEL_FILE)

    train = pd.read_parquet(PREPARED_DIR / "train.parquet")
    profile = build_profile(train[train[schema.TARGET] == 0], schema.FEATURES)
    write_json(REFERENCE_PROFILE, profile)

    test = pd.read_parquet(PREPARED_DIR / "test.parquet")
    future = pd.read_parquet(PREPARED_DIR / "future.parquet")
    datasets = {"test": test} | {
        f"future_{day}": part for day, part in future.groupby(schema.DAY, sort=False)
    }

    report = {"reference_benign_flows": profile["rows"]}
    for name, df in datasets.items():
        passed = df[model.predict_proba(df[schema.FEATURES])[:, 1] < threshold]
        summary = summarize(psi(profile, passed), params["feature_threshold"], params["share_threshold"])
        report[name] = {"passed_as_benign": len(passed), "hidden_attacks": int(passed[schema.TARGET].sum())}
        report[name] |= summary
        print(
            f"{name:<17} drift share {summary['drift_share']:.3f}  drift={summary['drift']}  "
            f"({report[name]['hidden_attacks']:,} hidden attacks in {len(passed):,} flows let through)"
        )
    write_json(REPORTS_DIR / "drift.json", report)


if __name__ == "__main__":
    main()
