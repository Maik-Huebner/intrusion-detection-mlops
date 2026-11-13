"""Quality gate: is the freshly trained model good enough to be promoted?

Compares ``metrics.json`` (test set) against the thresholds in ``params.yaml``. Exit code 0 means
passed, 1 means failed, so CI can stop a bad model before it reaches the registry or production.
On GitHub Actions the result table is also written to the job summary.
"""

import os
import sys

from ids.config import METRICS_FILE, load_params
from ids.io import read_json

# (metric, threshold key, comparison)
CHECKS = [
    ("detection_rate", "min_detection_rate", "min"),
    ("false_alarm_rate", "max_false_alarm_rate", "max"),
    ("f1", "min_f1", "min"),
]


def evaluate_gate(metrics: dict, thresholds: dict) -> tuple[bool, list[tuple[str, float, float, bool]]]:
    rows = []
    for metric, key, kind in CHECKS:
        value, limit = metrics[metric], thresholds[key]
        ok = value is not None and (value >= limit if kind == "min" else value <= limit)
        rows.append((metric, value, limit, ok))
    return all(r[3] for r in rows), rows


def main() -> None:
    passed, rows = evaluate_gate(read_json(METRICS_FILE)["test"], load_params("quality_gate"))
    verdict = "PASSED" if passed else "FAILED"
    table = "\n".join(
        ["| metric | value | threshold | result |", "|---|---|---|---|"]
        + [f"| {m} | {v} | {limit} | {'ok' if ok else 'FAIL'} |" for m, v, limit, ok in rows]
    )
    print(f"Quality gate {verdict}\n{table}")

    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"## Quality gate: {verdict}\n\n{table}\n")

    if not passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
