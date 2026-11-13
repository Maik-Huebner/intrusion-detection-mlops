"""Stage ``evaluate``: how well does the detector catch attacks?

The model is scored twice:

* on ``test``   - held-out flows from the training days (attack types the model knows)
* on ``future`` - the following days, including attack types the model has never seen

The gap between the two is the drift the MLOps loop has to close.

Outputs: ``metrics.json`` (tracked by ``dvc metrics``) and ``reports/detection.json`` (per attack type).
"""

import joblib
import pandas as pd

from ids import schema
from ids.config import METRICS_FILE, MODEL_FILE, PREPARED_DIR, REPORTS_DIR, load_params
from ids.io import write_json
from ids.metrics import correct_by_group, detection_metrics


def score(model, df: pd.DataFrame, threshold: float) -> tuple[dict, dict]:
    df = df.reset_index(drop=True)
    scores = model.predict_proba(df[schema.FEATURES])[:, 1]
    y_pred = (scores >= threshold).astype(int)
    metrics = detection_metrics(df[schema.TARGET], scores, threshold)
    details = {
        "by_category": correct_by_group(df, y_pred, schema.CATEGORY),
        "by_label": correct_by_group(df, y_pred, schema.LABEL),
    }
    return metrics, details


def main() -> None:
    threshold = load_params("evaluate")["threshold"]
    model = joblib.load(MODEL_FILE)
    test = pd.read_parquet(PREPARED_DIR / "test.parquet")
    future = pd.read_parquet(PREPARED_DIR / "future.parquet")

    metrics, details = {}, {}
    metrics["test"], details["test"] = score(model, test, threshold)
    if len(future):
        metrics["future"], details["future"] = score(model, future, threshold)
        for day, part in future.groupby(schema.DAY, sort=False):
            metrics[f"future_{day}"], details[f"future_{day}"] = score(model, part, threshold)

    write_json(METRICS_FILE, metrics)
    write_json(REPORTS_DIR / "detection.json", details)

    for name, m in metrics.items():
        print(
            f"{name:<17} detection rate {m['detection_rate']}  false alarm rate {m['false_alarm_rate']}  "
            f"F1 {m['f1']}  ({m['attacks']:,} attacks / {m['flows']:,} flows)"
        )


if __name__ == "__main__":
    main()
