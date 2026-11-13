"""Stage ``validate``: data quality checks before any model sees the data.

The rules live in :func:`validate_frame` so they are unit-tested. A non-zero exit code stops
``dvc repro`` and fails the CI run.
"""

import sys

import pandas as pd

from ids import schema
from ids.config import INTERIM_DIR, REPORTS_DIR
from ids.io import write_json

MIN_ROWS = 1000


def validate_frame(df: pd.DataFrame) -> list[str]:
    """Return a list of human-readable problems (empty list = data is valid)."""
    required = schema.FEATURES + [schema.LABEL, schema.CATEGORY, schema.TARGET, schema.DAY]
    missing = [c for c in required if c not in df.columns]
    if missing:
        return [f"missing columns: {missing}"]

    errors = []
    if len(df) < MIN_ROWS:
        errors.append(f"too few rows: {len(df)} < {MIN_ROWS}")

    if n := int(df[schema.FEATURES].isna().sum().sum()):
        errors.append(f"missing feature values: {n}")

    unknown = sorted(df.loc[df[schema.CATEGORY] == schema.UNKNOWN_CATEGORY, schema.LABEL].unique())
    if unknown:
        errors.append(f"unknown labels: {unknown}")

    if n := int(df[schema.LABEL].str.contains("Attempted").sum()):
        errors.append(f"{n} rows still labelled as 'Attempted'")

    if n := int(((df[schema.LABEL] == schema.BENIGN) != (df[schema.TARGET] == 0)).sum()):
        errors.append(f"target does not match label in {n} rows")

    if n := int((df[schema.COUNTER_FEATURES] < 0).sum().sum()):
        errors.append(f"negative packet/byte/flag counters: {n}")

    protocols = sorted(set(df["Protocol"].unique()) - schema.KNOWN_PROTOCOLS)
    if protocols:
        errors.append(f"unknown protocols: {protocols}")

    if n := int(((df["Dst Port"] < 0) | (df["Dst Port"] > 65535)).sum()):
        errors.append(f"destination port outside 0-65535: {n}")

    return errors


def main() -> None:
    report, failures = {}, []
    for day in schema.DAYS:
        df = pd.read_parquet(INTERIM_DIR / f"{day}.parquet")
        errors = validate_frame(df)
        report[day] = {"rows": len(df), "ok": not errors, "errors": errors}
        failures += [f"{day}: {e}" for e in errors]

    write_json(REPORTS_DIR / "validate.json", report)

    if failures:
        print("Validation FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)
    print(f"Validation passed: {sum(r['rows'] for r in report.values()):,} flows over {len(report)} days")


if __name__ == "__main__":
    main()
