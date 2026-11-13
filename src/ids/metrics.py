"""Detection metrics that matter in a Security Operations Center (SOC).

Accuracy is misleading for intrusion detection: if 80 % of the traffic is benign, a model that
never raises an alarm is 80 % "accurate" and catches nothing. We report instead:

* ``detection_rate``      share of attacks that raise an alarm (recall, true positive rate)
* ``false_alarm_rate``    share of benign flows that raise an alarm (false positive rate)
* ``precision``           share of alarms that are real attacks
* ``f1``                  harmonic mean of precision and detection rate
* ``pr_auc``              area under the precision-recall curve, independent of the threshold

Undefined values (e.g. a detection rate on a set without attacks) are ``None``.
"""

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix

from ids import schema

DECIMALS = 4  # rounding keeps metrics.json stable across platforms


def _ratio(numerator: float, denominator: float) -> float | None:
    return round(float(numerator / denominator), DECIMALS) if denominator else None


def detection_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=float)
    y_pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    pr_auc = None
    if tp + fn and tn + fp:
        pr_auc = round(float(average_precision_score(y_true, scores)), DECIMALS)

    return {
        "flows": len(y_true),
        "attacks": int(tp + fn),
        "alarms": int(tp + fp),
        "detection_rate": _ratio(tp, tp + fn),
        "false_alarm_rate": _ratio(fp, fp + tn),
        "precision": _ratio(tp, tp + fp),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "pr_auc": pr_auc,
    }


def correct_by_group(df: pd.DataFrame, y_pred: np.ndarray, column: str) -> dict:
    """Share of correctly classified flows per group.

    For an attack group this is its detection rate; for the benign group it is the share of flows
    that did *not* raise a false alarm.
    """
    correct = pd.Series(np.asarray(y_pred) == df[schema.TARGET].to_numpy(), index=df.index)
    grouped = correct.groupby(df[column].to_numpy(), sort=True)
    return {
        str(group): {"flows": int(n), "correct": int(c), "share": round(float(c / n), DECIMALS)}
        for group, n, c in zip(grouped.size().index, grouped.size(), grouped.sum(), strict=True)
    }
