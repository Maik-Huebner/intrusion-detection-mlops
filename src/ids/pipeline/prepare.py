"""Stage ``prepare``: raw CSVs inside the ZIP -> one clean Parquet file per weekday.

1. Flows flagged as *attempted* attacks are relabelled as benign. These flows belonged to an attack
   script but carry no malicious payload (e.g. the target never answered). This follows the
   recommendation of the dataset authors (Liu, Engelen et al., IEEE CNS 2022); keeping them as
   attacks teaches the model to flag harmless traffic.
2. Identifier columns are dropped (see ``ids.schema.ID_COLUMNS``).
3. Rows with infinite or missing feature values are dropped and counted in the report.
4. Rows with a negative ``Fwd/Bwd Header Length`` are dropped. All of them lie in -32768..32767:
   a 16-bit integer overflow in CICFlowMeter for long flows. The true value cannot be recovered
   (a positive value may have wrapped as well), so these ~0.03 % of flows are excluded.
5. Features are stored as float32: half the memory, more than enough precision for tree models.

Outputs: ``data/interim/<day>.parquet`` and ``reports/prepare.json``.
"""

import zipfile

import numpy as np
import pandas as pd

from ids import schema
from ids.config import INTERIM_DIR, RAW_ARCHIVE, REPORTS_DIR
from ids.io import write_json


def prepare_day(raw: pd.DataFrame, day: str) -> tuple[pd.DataFrame, dict]:
    """Clean the raw flows of one day. Returns the table and summary statistics for the report."""
    expected = set(schema.ID_COLUMNS + schema.FEATURES + [schema.RAW_LABEL, schema.RAW_ATTEMPTED])
    missing = sorted(expected - set(raw.columns))
    if missing:
        raise ValueError(f"{day}: raw data is missing columns {missing}")

    attempted = raw[schema.RAW_ATTEMPTED] != -1
    label = raw[schema.RAW_LABEL].where(~attempted, schema.BENIGN)

    features = raw[schema.FEATURES].astype("float64").replace([np.inf, -np.inf], np.nan)
    non_finite = features.isna().any(axis=1)
    overflow = (features[schema.OVERFLOW_FEATURES] < 0).any(axis=1) & ~non_finite
    invalid = non_finite | overflow

    df = features[~invalid].astype("float32")
    df[schema.LABEL] = label[~invalid].astype("string")
    df[schema.CATEGORY] = df[schema.LABEL].map(schema.attack_category).astype("string")
    df[schema.TARGET] = (df[schema.LABEL] != schema.BENIGN).astype("int8")
    df[schema.DAY] = day
    df = df.reset_index(drop=True)

    stats = {
        "rows_raw": len(raw),
        "attempted_relabelled_benign": int(attempted.sum()),
        "dropped_non_finite": int(non_finite.sum()),
        "dropped_header_overflow": int(overflow.sum()),
        "rows": len(df),
        "attacks": int(df[schema.TARGET].sum()),
        "labels": {str(k): int(v) for k, v in df[schema.LABEL].value_counts().items()},
    }
    return df, stats


def main() -> None:
    INTERIM_DIR.mkdir(parents=True, exist_ok=True)
    report = {}
    with zipfile.ZipFile(RAW_ARCHIVE) as archive:
        for day in schema.DAYS:
            with archive.open(f"{day}.csv") as fh:
                raw = pd.read_csv(fh, engine="pyarrow")
            df, stats = prepare_day(raw, day)
            df.to_parquet(INTERIM_DIR / f"{day}.parquet", index=False)
            report[day] = stats
            print(
                f"{day:<10} {stats['rows']:>9,} flows  {stats['attacks']:>7,} attacks  "
                f"(attempted -> benign: {stats['attempted_relabelled_benign']:,}, dropped: "
                f"{stats['dropped_non_finite']:,} non-finite, {stats['dropped_header_overflow']:,} overflow)"
            )
    write_json(REPORTS_DIR / "prepare.json", report)


if __name__ == "__main__":
    main()
