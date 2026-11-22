"""Experiment tracking and model registry with MLflow.

``log``      Log the current pipeline result (params, metrics, reports, model, lineage) as an MLflow
             run and register it as a new version of the model.
``promote``  Champion/challenger: the newest version becomes ``@challenger``. It replaces
             ``@champion`` only if it passes the quality gate *and* beats the champion on the same,
             most recent labelled data. Comparing the two models on the same data matters: after a
             drift the champion's own test score says nothing about today's traffic.
``champion`` Point ``@champion`` to a given version by hand (rollback).

Usage::

    uv run python -m ids.registry log
    uv run python -m ids.registry promote
    uv run python -m ids.registry champion 3

The tracking server comes from ``MLFLOW_TRACKING_URI`` (default: local ``mlflow.db``).
"""

import argparse
import os

import joblib
import mlflow
import pandas as pd
from mlflow import MlflowClient
from mlflow.exceptions import MlflowException

from ids import schema
from ids.config import METRICS_FILE, MODEL_FILE, PREPARED_DIR, REPORTS_DIR, load_params
from ids.io import read_json
from ids.lineage import data_versions, flatten, git_state
from ids.metrics import detection_metrics
from ids.quality_gate import evaluate_gate

EXPERIMENT = "intrusion-detection"
MODEL_NAME = "ids-detector"
CHAMPION, CHALLENGER = "champion", "challenger"
# The challenger must beat the champion's F1 by at least this margin to replace it.
MIN_IMPROVEMENT = 0.005

# MLflow stores scikit-learn models with skops instead of pickle: loading a skops file cannot run
# arbitrary code, only types on an allow-list are rebuilt. Gradient boosting needs exactly one type
# beyond the skops defaults, so we trust that one and nothing else.
SKOPS_TRUSTED_TYPES = ["sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor"]


def load_registered_model(model_uri: str):
    """Load a model from *our own* registry. MLflow refuses any deserialisation unless explicitly allowed."""
    os.environ.setdefault("MLFLOW_ALLOW_PICKLE_DESERIALIZATION", "true")
    return mlflow.sklearn.load_model(model_uri)


def _client() -> MlflowClient:
    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    return MlflowClient()


def log_run() -> str:
    """Log the pipeline output as a run and register the model. Returns the new version."""
    client = _client()
    mlflow.set_experiment(EXPERIMENT)
    params = load_params()
    metrics = read_json(METRICS_FILE)
    split = params["split"]
    run_name = f"train {'+'.join(d[:3] for d in split['train_days'])}"

    with mlflow.start_run(run_name=run_name) as run:
        mlflow.log_params(flatten({k: params[k] for k in ("split", "train", "evaluate")}))
        mlflow.log_metrics({k: v for k, v in flatten(metrics).items() if v is not None})
        mlflow.set_tags({**data_versions(), **git_state(), "train_days": ",".join(split["train_days"])})
        for path in sorted(REPORTS_DIR.glob("*")):
            mlflow.log_artifact(str(path), artifact_path="reports")
        mlflow.log_artifact("dvc.lock")

        model = joblib.load(MODEL_FILE)
        example = pd.read_parquet(PREPARED_DIR / "test.parquet").head(5)[schema.FEATURES]
        info = mlflow.sklearn.log_model(
            sk_model=model, name="model", input_example=example, skops_trusted_types=SKOPS_TRUSTED_TYPES
        )

    version = mlflow.register_model(info.model_uri, MODEL_NAME).version
    client.set_model_version_tag(MODEL_NAME, version, "run_id", run.info.run_id)
    print(f"run {run.info.run_id} ({run_name}) -> {MODEL_NAME} version {version}")
    return version


def _f1_on_recent_data(model_uri: str) -> float | None:
    """F1 of a registered model on the newest labelled data (the current test set)."""
    test = pd.read_parquet(PREPARED_DIR / "test.parquet")
    scores = load_registered_model(model_uri).predict_proba(test[schema.FEATURES])[:, 1]
    return detection_metrics(test[schema.TARGET], scores, load_params("evaluate")["threshold"])["f1"]


def promote() -> None:
    client = _client()
    newest = max(client.search_model_versions(f"name='{MODEL_NAME}'"), key=lambda v: int(v.version))
    client.set_registered_model_alias(MODEL_NAME, CHALLENGER, newest.version)
    print(f"version {newest.version} is now @{CHALLENGER}")

    passed, _ = evaluate_gate(read_json(METRICS_FILE)["test"], load_params("quality_gate"))
    if not passed:
        print("quality gate failed -> champion unchanged")
        return

    try:
        champion = client.get_model_version_by_alias(MODEL_NAME, CHAMPION)
    except MlflowException:
        client.set_registered_model_alias(MODEL_NAME, CHAMPION, newest.version)
        client.delete_registered_model_alias(MODEL_NAME, CHALLENGER)
        print(f"no champion yet -> version {newest.version} is now @{CHAMPION}")
        return

    if champion.version == newest.version:
        print(f"version {newest.version} already is @{CHAMPION}")
        return

    f1_champion = _f1_on_recent_data(f"models:/{MODEL_NAME}@{CHAMPION}")
    f1_challenger = _f1_on_recent_data(f"models:/{MODEL_NAME}@{CHALLENGER}")
    print(
        f"F1 on recent data: champion v{champion.version}={f1_champion}, "
        f"challenger v{newest.version}={f1_challenger}"
    )

    if f1_challenger is not None and (f1_champion is None or f1_challenger >= f1_champion + MIN_IMPROVEMENT):
        client.set_registered_model_alias(MODEL_NAME, CHAMPION, newest.version)
        client.delete_registered_model_alias(MODEL_NAME, CHALLENGER)
        print(f"challenger wins -> version {newest.version} is now @{CHAMPION}")
    else:
        print(f"challenger not better by {MIN_IMPROVEMENT} -> version {champion.version} stays @{CHAMPION}")


def set_champion(version: str) -> None:
    client = _client()
    client.get_model_version(MODEL_NAME, version)  # fails loudly if the version does not exist
    client.set_registered_model_alias(MODEL_NAME, CHAMPION, version)
    print(f"@{CHAMPION} -> version {version}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("log", help="log the current pipeline result and register the model")
    commands.add_parser("promote", help="champion/challenger promotion of the newest version")
    rollback = commands.add_parser("champion", help="set @champion to a version (rollback)")
    rollback.add_argument("version")
    args = parser.parse_args()

    if args.command == "log":
        log_run()
    elif args.command == "promote":
        promote()
    else:
        set_champion(args.version)


if __name__ == "__main__":
    main()
