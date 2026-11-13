"""Stage ``train``: fit the detector and persist it.

``HistGradientBoostingClassifier`` is scikit-learn's histogram-based gradient boosting (the same
idea as LightGBM): fast on millions of rows, no feature scaling needed, robust to the heavy-tailed
flow statistics, and deterministic for a fixed ``random_state``.
"""

import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from ids import schema
from ids.config import MODEL_FILE, PREPARED_DIR, load_params


def build_model(params: dict) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        max_iter=params["max_iter"],
        learning_rate=params["learning_rate"],
        max_leaf_nodes=params["max_leaf_nodes"],
        l2_regularization=params["l2_regularization"],
        early_stopping=False,  # early stopping would add a second, hidden random split
        random_state=params["random_state"],
    )


def main() -> None:
    params = load_params("train")
    train = pd.read_parquet(PREPARED_DIR / "train.parquet")

    model = build_model(params)
    model.fit(train[schema.FEATURES], train[schema.TARGET])

    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    print(f"trained on {len(train):,} flows with {params} -> {MODEL_FILE}")


if __name__ == "__main__":
    main()
