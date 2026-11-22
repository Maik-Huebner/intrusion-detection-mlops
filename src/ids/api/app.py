"""Real-time scoring API with Prometheus metrics and a live drift monitor.

Run locally::

    uv run uvicorn ids.api.app:app --reload

Configuration (environment variables):

* ``MODEL_URI``    MLflow model URI, e.g. ``models:/ids-detector@champion`` (needs MLFLOW_TRACKING_URI).
                   Rollout = move the alias in the registry, restart the API. If the registry cannot
                   be reached, the API falls back to the baked-in model and reports it (``/model``,
                   metric ``ids_model_info``) instead of not starting at all.
* ``MODEL_PATH``   joblib model file (default ``models/model.joblib``)
* ``PROFILE_PATH`` drift reference profile for that file (default ``models/reference_profile.json``)
* ``FAMILY_PATH``  attack type model for that file (default ``models/family.joblib``)
* ``LLM_*``        analyst notes via an OpenAI-compatible LLM, see ``ids.api.llm``
* ``THRESHOLD``    alarm threshold (default: ``evaluate.threshold`` from params.yaml, else 0.5)
"""

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ids import __version__, schema
from ids.api import llm
from ids.api import monitoring as m
from ids.api.schemas import (
    BatchRequest,
    BatchResponse,
    DriftStatus,
    Explanation,
    Flow,
    ModelInfo,
    Prediction,
    UnusualFeature,
)
from ids.config import FAMILY_MODEL_FILE, MODEL_FILE, PARAMS_FILE, REFERENCE_PROFILE, load_params
from ids.drift import unusual_features
from ids.io import read_json
from ids.pipeline.family import family_of, predict_types

log = logging.getLogger("uvicorn.error")
DRIFT_DEFAULTS = {"feature_threshold": 0.2, "share_threshold": 0.1, "window": 1000}

state: dict = {}


def _load_file_model() -> dict:
    path = Path(os.getenv("MODEL_PATH", str(MODEL_FILE)))
    profile_path = Path(os.getenv("PROFILE_PATH", str(REFERENCE_PROFILE)))
    family_path = Path(os.getenv("FAMILY_PATH", str(FAMILY_MODEL_FILE)))
    return {
        "model": joblib.load(path),
        "profile": read_json(profile_path) if profile_path.exists() else None,
        "family_model": joblib.load(family_path) if family_path.exists() else None,
        "source": str(path),
        "version": "file",
    }


def _load_model() -> dict:
    if uri := os.getenv("MODEL_URI"):
        try:
            from ids.registry import load_serving_bundle  # needs mlflow (api group: mlflow-skinny)

            return load_serving_bundle(uri) | {"fallback": False}
        except Exception as exc:  # registry down, alias missing, ...: keep detecting with what we have
            log.error("could not load %s (%s) - serving the baked-in model instead", uri, exc)
            return _load_file_model() | {"fallback": True}
    return _load_file_model() | {"fallback": False}


def _settings() -> tuple[float, dict, float]:
    params = load_params() if PARAMS_FILE.exists() else {}
    threshold = float(os.getenv("THRESHOLD") or params.get("evaluate", {}).get("threshold", 0.5))
    min_confidence = float(params.get("family", {}).get("min_confidence", 0.9))
    return threshold, DRIFT_DEFAULTS | params.get("drift", {}), min_confidence


@asynccontextmanager
async def lifespan(_: FastAPI):
    state.update(_load_model())  # once at startup, not per request
    state["threshold"], drift, state["min_confidence"] = _settings()
    state["monitor"] = (
        m.DriftMonitor(
            state["profile"], drift["feature_threshold"], drift["share_threshold"], drift["window"]
        )
        if state["profile"]
        else None
    )
    m.MODEL.info(
        {"source": state["source"], "version": state["version"], "fallback": str(state["fallback"]).lower()}
    )
    log.info("serving %s (version %s), drift monitoring %s, attack types %s, LLM notes %s", state["source"],
             state["version"], "on" if state["monitor"] else "off", "on" if state["family_model"] else "off",
             llm.settings()["model"] if llm.is_configured() else "off (templates)")  # fmt: skip
    yield
    state.clear()


app = FastAPI(
    title="Intrusion Detection API",
    description="Scores network flows (CICFlowMeter features) as benign or attack, and watches for drift.",
    version=__version__,
    lifespan=lifespan,
)


@app.middleware("http")
async def record_metrics(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    route = request.scope.get("route")
    path = route.path if route else "unmatched"  # route template: no unbounded label values
    if path != "/metrics":
        m.REQUESTS.labels(path, request.method, str(response.status_code)).inc()
        m.LATENCY.labels(path).observe(time.perf_counter() - start)
    return response


def _predict(flows: list) -> list[Prediction]:
    frame = pd.DataFrame([f.model_dump(by_alias=True) for f in flows], columns=schema.FEATURES)
    try:
        probabilities = state["model"].predict_proba(frame)[:, 1]
    except Exception as exc:  # e.g. a model trained on a different feature set
        raise HTTPException(status_code=500, detail=f"model could not score the request: {exc}") from exc

    alarms = probabilities >= state["threshold"]
    m.FLOWS.labels("attack").inc(int(alarms.sum()))
    m.FLOWS.labels("benign").inc(int((~alarms).sum()))
    for p in probabilities:
        m.PROBABILITY.observe(float(p))
    if state["monitor"]:
        state["monitor"].observe(frame[~alarms])

    predictions = [
        Prediction(is_attack=bool(alarm), attack_probability=round(float(p), 4))
        for p, alarm in zip(probabilities, alarms, strict=True)
    ]
    if state["family_model"] is not None and alarms.any():  # the type is only asked for alarms
        types, confidence = predict_types(state["family_model"], frame[alarms], state["min_confidence"])
        alarm_rows = [i for i, alarm in enumerate(alarms) if alarm]
        for i, attack_type, conf in zip(alarm_rows, types, confidence, strict=True):
            family = family_of(attack_type)
            predictions[i].attack_type, predictions[i].family = str(attack_type), family
            predictions[i].type_confidence = round(float(conf), 4)
            m.ALARMS_BY_FAMILY.labels(family).inc()
    return predictions


@app.get("/health", tags=["info"])
def health() -> dict:
    return {"status": "ok"}


@app.get("/model", tags=["info"])
def model_info() -> ModelInfo:
    return ModelInfo(
        source=state["source"],
        version=state["version"],
        fallback=state["fallback"],
        threshold=state["threshold"],
        features=len(schema.FEATURES),
        drift_monitoring=state["monitor"] is not None,
    )


@app.get("/drift", tags=["info"])
def drift_status() -> DriftStatus:
    """Current result of the live drift monitor (also exported as Prometheus metrics)."""
    monitor = state["monitor"]
    if monitor is None:
        raise HTTPException(status_code=404, detail="no reference profile loaded: drift monitoring is off")
    last = monitor.last or {}
    return DriftStatus(window_flows=len(monitor.window), drift=last.get("drift"), **{
        k: last[k] for k in ("drift_share", "drifted_features", "top_features") if k in last
    })  # fmt: skip


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/predict", tags=["scoring"])
def predict(flow: Flow) -> Prediction:  # type: ignore[valid-type]
    return _predict([flow])[0]


@app.post("/predict/batch", tags=["scoring"])
def predict_batch(request: BatchRequest) -> BatchResponse:
    predictions = _predict(request.flows)
    return BatchResponse(predictions=predictions, alarms=sum(p.is_attack for p in predictions))


@app.post("/explain", tags=["scoring"])
def explain(flow: Flow) -> Explanation:  # type: ignore[valid-type]
    """Score one flow and write a note for the analyst (LLM with rule check, template as fallback)."""
    prediction = _predict([flow])[0]
    values = flow.model_dump(by_alias=True)
    unusual = unusual_features(state["profile"], values) if state["profile"] else []
    monitor = state["monitor"]
    drift_warning = bool(monitor and monitor.last and monitor.last["drift"])
    base = {"prediction": prediction, "unusual_features": [UnusualFeature(**u) for u in unusual],
            "drift_warning": drift_warning}  # fmt: skip

    if not prediction.is_attack:
        return Explanation(**base, note=llm.no_alarm_note(prediction.attack_probability), source="no_alarm")

    ctx = {
        "attack_type": prediction.attack_type or "unbekannter Angriff",
        "family": prediction.family or "unbekannt",
        "type_confidence": prediction.type_confidence or 0.0,
        "attack_probability": prediction.attack_probability,
        "dst_port": values["Dst Port"],
        "protocol": values["Protocol"],
        "unusual_features": unusual,
        "drift_warning": drift_warning,
    }
    fallback = {"note": llm.fallback_note(ctx), "source": "fallback", "prompt_version": "template"}
    if not llm.is_configured():
        m.LLM_REQUESTS.labels("not_configured").inc()
        return Explanation(**base, **fallback, reason="not_configured")
    try:
        answer = llm.generate(ctx)
    except Exception as exc:  # timeout, connection refused, rate limit ...: the analyst still gets a note
        m.LLM_REQUESTS.labels("error").inc()
        m.LLM_ERRORS.labels(type(exc).__name__).inc()
        log.warning("LLM failed (%s) - template note", exc)
        return Explanation(**base, **fallback, reason=type(exc).__name__)

    m.LLM_LATENCY.observe(answer["seconds"])
    if answer["tokens"]:
        m.LLM_TOKENS.inc(answer["tokens"])
    rules = llm.check_rules(answer["text"], ctx)
    if not all(rules.values()):
        m.LLM_REQUESTS.labels("rejected").inc()
        return Explanation(**base, **fallback, reason="rules", rules=rules, llm_model=answer["llm_model"],
                           seconds=answer["seconds"])  # fmt: skip
    m.LLM_REQUESTS.labels("ok").inc()
    return Explanation(**base, note=answer["text"], source="llm", rules=rules, llm_model=answer["llm_model"],
                       prompt_version=llm.PROMPT_VERSION, seconds=answer["seconds"])  # fmt: skip
