"""Stage ``split``: what is the past (to learn from) and what is the future?

This is the heart of the drift scenario. A deployed model only knows yesterday's attacks, so we split
by *time*, not randomly across the whole week::

    train_days  -> train.parquet (80 %) + test.parquet (20 %, same attack types, never trained on)
    future_days -> future.parquet       (traffic the model only meets in production)

Exact duplicates (same features *and* label) are removed before splitting. Otherwise the same flow
lands in train and test and the offline score looks better than the model really is.
"""

import pandas as pd
from sklearn.model_selection import train_test_split

from ids import schema
from ids.config import INTERIM_DIR, PREPARED_DIR, REPORTS_DIR, load_params
from ids.io import write_json


def load_days(days: list[str]) -> pd.DataFrame:
    return pd.concat([pd.read_parquet(INTERIM_DIR / f"{d}.parquet") for d in days], ignore_index=True)


def summarize(df: pd.DataFrame) -> dict:
    return {
        "rows": len(df),
        "days": sorted(df[schema.DAY].unique().tolist()),
        "categories": {str(k): int(v) for k, v in df[schema.CATEGORY].value_counts().items()},
    }


def main() -> None:
    params = load_params("split")

    past = load_days(params["train_days"])
    before = len(past)
    past = past.drop_duplicates(subset=schema.FEATURES + [schema.LABEL], ignore_index=True)

    train, test = train_test_split(
        past,
        test_size=params["test_size"],
        stratify=past[schema.LABEL],
        random_state=params["random_state"],
    )
    future = load_days(params["future_days"]) if params["future_days"] else past.iloc[0:0]

    PREPARED_DIR.mkdir(parents=True, exist_ok=True)
    for name, df in (("train", train), ("test", test), ("future", future)):
        df.to_parquet(PREPARED_DIR / f"{name}.parquet", index=False)

    report = {"duplicates_removed": before - len(past), "train": summarize(train), "test": summarize(test)}
    if len(future):
        report["future"] = summarize(future)
    write_json(REPORTS_DIR / "split.json", report)

    print(f"duplicates removed: {before - len(past):,}")
    print(f"train  {len(train):>9,} flows  ({', '.join(params['train_days'])})")
    print(f"test   {len(test):>9,} flows  (same days, held out)")
    print(f"future {len(future):>9,} flows  ({', '.join(params['future_days']) or '-'})")


if __name__ == "__main__":
    main()
