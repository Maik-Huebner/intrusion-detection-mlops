import numpy as np
import pandas as pd

from ids import schema
from ids.metrics import correct_by_group, detection_metrics


def test_detection_metrics_on_known_confusion_matrix():
    # 4 attacks (3 detected), 6 benign (1 false alarm)
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0])
    scores = np.array([0.9, 0.8, 0.7, 0.1, 0.6, 0.2, 0.1, 0.1, 0.0, 0.0])

    m = detection_metrics(y_true, scores, threshold=0.5)

    assert m["attacks"] == 4
    assert m["alarms"] == 4
    assert m["detection_rate"] == 0.75
    assert m["false_alarm_rate"] == round(1 / 6, 4)
    assert m["precision"] == 0.75
    assert m["f1"] == 0.75
    assert 0 < m["pr_auc"] <= 1


def test_undefined_metrics_are_none():
    m = detection_metrics(np.zeros(5), np.zeros(5), threshold=0.5)
    assert m["detection_rate"] is None
    assert m["precision"] is None
    assert m["pr_auc"] is None
    assert m["false_alarm_rate"] == 0.0


def test_correct_by_group():
    df = pd.DataFrame(
        {schema.TARGET: [1, 1, 1, 0, 0], schema.CATEGORY: ["DoS", "DoS", "PortScan", "Benign", "Benign"]}
    )
    result = correct_by_group(df, np.array([1, 0, 0, 0, 1]), schema.CATEGORY)

    assert result["DoS"] == {"flows": 2, "correct": 1, "share": 0.5}
    assert result["PortScan"]["share"] == 0.0
    assert result["Benign"]["share"] == 0.5
