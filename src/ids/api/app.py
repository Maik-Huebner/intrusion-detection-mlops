"""Real-time scoring API.

Run locally::

    uv run uvicorn ids.api.app:app --reload

Configuration (environment variables):

* ``MODEL_URI``  MLflow model URI, e.g. ``models:/ids-detector@champion`` (needs MLFLOW_TRACKING_URI).
                 If unset, the model file of the DVC pipeline is used.
* ``MODEL_PATH`` path to a joblib model file (default ``models/model.joblib``).
* ``THRESHOLD``  alarm threshold (default: ``evaluate.threshold`` from params.yaml, else 0.5).
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException

from ids import __version__, schema
from ids.api.schemas import BatchRequest, BatchResponse, Flow, ModelInfo, Prediction
from ids.config import MODEL_FILE, PARAMS_FILE, load_params

state: dict = {}


def _load_model():
    if uri := os.getenv("MODEL_URI"):
        from ids.registry import load_registered_model  # needs the tracking group (mlflow)

        return load_registered_model(uri), uri
    path = Path(os.getenv("MODEL_PATH", str(MODEL_FILE)))
    return joblib.load(path), str(path)


def _threshold() -> float:
    if value := os.getenv("THRESHOLD"):
        return float(value)
    return float(load_params("evaluate")["threshold"]) if PARAMS_FILE.exists() else 0.5


@asynccontextmanager
async def lifespan(_: FastAPI):
    state["model"], state["source"] = _load_model()  # once at startup, not per request
    state["threshold"] = _threshold()
    yield
    state.clear()


app = FastAPI(
    title="Intrusion Detection API",
    description="Scores network flows (CICFlowMeter features) as benign or attack.",
    version=__version__,
    lifespan=lifespan,
)


def _predict(flows: list) -> list[Prediction]:
    frame = pd.DataFrame([f.model_dump(by_alias=True) for f in flows], columns=schema.FEATURES)
    try:
        probabilities = state["model"].predict_proba(frame)[:, 1]
    except Exception as exc:  # e.g. a model trained on a different feature set
        raise HTTPException(status_code=500, detail=f"model could not score the request: {exc}") from exc
    threshold = state["threshold"]
    return [
        Prediction(is_attack=bool(p >= threshold), attack_probability=round(float(p), 4))
        for p in probabilities
    ]


@app.get("/health", tags=["info"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/model", tags=["info"])
def model_info() -> ModelInfo:
    return ModelInfo(source=state["source"], threshold=state["threshold"], features=len(schema.FEATURES))


@app.post("/predict", tags=["scoring"])
def predict(flow: Flow) -> Prediction:  # type: ignore[valid-type]
    return _predict([flow])[0]


@app.post("/predict/batch", tags=["scoring"])
def predict_batch(request: BatchRequest) -> BatchResponse:
    predictions = _predict(request.flows)
    return BatchResponse(predictions=predictions, alarms=sum(p.is_attack for p in predictions))
