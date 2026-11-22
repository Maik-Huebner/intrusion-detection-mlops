"""Evaluate the *running* API the way a client uses it: quality, latency, throughput, robustness.

1. Quality     held-out test flows over HTTP: detection and false alarm rate of the served model
2. Latency     single-flow requests to /predict: p50, p95, p99 in milliseconds
3. Throughput  flows per second through /predict/batch
4. Robustness  invalid requests must be rejected with 422, not crash the service (500)

The result goes to ``reports/api_evaluation.json`` and to MLflow (experiment ``ids-api-evaluation``).

Usage (stack running)::

    MLFLOW_TRACKING_URI=http://127.0.0.1:5050 uv run python -m ids.evaluate_api
"""

import json
import os
import statistics
import time
import urllib.error
import urllib.request

import pandas as pd

from ids import schema
from ids.api.schemas import EXAMPLE_FLOW, MAX_BATCH
from ids.config import PREPARED_DIR, REPORTS_DIR, load_params
from ids.io import write_json
from ids.metrics import detection_metrics

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
EXPERIMENT = "ids-api-evaluation"


def _request(method: str, path: str, body=None) -> tuple[int, dict, float]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{API_URL}{path}", data=data, method=method, headers={"Content-Type": "application/json"}
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            status, payload = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        status, payload = error.code, {}
    return status, payload, (time.perf_counter() - start) * 1000


def main() -> None:
    _, model, _ = _request("GET", "/model")
    test = pd.read_parquet(PREPARED_DIR / "test.parquet").sample(20_000, random_state=0)
    flows = test[schema.FEATURES].astype(float).to_dict("records")

    # 1 + 3: quality and throughput through the batch endpoint
    scores, start = [], time.perf_counter()
    for i in range(0, len(flows), 1000):
        _, answer, _ = _request("POST", "/predict/batch", {"flows": flows[i : i + 1000]})
        scores += [p["attack_probability"] for p in answer["predictions"]]
    throughput = len(flows) / (time.perf_counter() - start)
    quality = detection_metrics(test[schema.TARGET], scores, model["threshold"])

    # 2: latency of single requests
    latencies = [_request("POST", "/predict", flow)[2] for flow in flows[:500]]
    q = statistics.quantiles(latencies, n=100)

    # 4: robustness
    cases = {
        "missing feature": ("/predict", {k: v for k, v in EXAMPLE_FLOW.items() if k != "Flow Duration"}),
        "port out of range": ("/predict", EXAMPLE_FLOW | {"Dst Port": 70_000}),
        "negative counter": ("/predict", EXAMPLE_FLOW | {"Total Fwd Packet": -1}),
        "text instead of number": ("/predict", EXAMPLE_FLOW | {"Flow Duration": "long"}),
        "empty batch": ("/predict/batch", {"flows": []}),
        "batch too large": ("/predict/batch", {"flows": [EXAMPLE_FLOW] * (MAX_BATCH + 1)}),
    }
    robustness = {name: _request("POST", path, body)[0] for name, (path, body) in cases.items()}
    rejected = sum(status == 422 for status in robustness.values())

    result = {
        "model_source": model["source"],
        "model_version": model["version"],
        "test_flows": len(flows),
        "detection_rate": quality["detection_rate"],
        "false_alarm_rate": quality["false_alarm_rate"],
        "f1": quality["f1"],
        "latency_p50_ms": round(q[49], 1),
        "latency_p95_ms": round(q[94], 1),
        "latency_p99_ms": round(q[98], 1),
        "throughput_flows_per_s": round(throughput),
        "robustness_rejected_422": f"{rejected}/{len(cases)}",
        "robustness": robustness,
    }
    write_json(REPORTS_DIR / "api_evaluation.json", result)
    for key, value in result.items():
        if key != "robustness":
            print(f"{key:<26} {value}")
    for name, status in robustness.items():
        print(f"  {name:<24} -> {status} {'ok' if status == 422 else 'UNEXPECTED'}")

    import mlflow  # tracking group; imported late so the evaluation itself needs no MLflow

    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"api model v{model['version']}"):
        mlflow.log_params({"model_source": model["source"], "model_version": model["version"],
                           "threshold": model["threshold"], "test_flows": len(flows)})  # fmt: skip
        mlflow.log_metrics({k: v for k, v in result.items() if isinstance(v, int | float) and v is not None})
        mlflow.log_dict(robustness, "robustness.json")
        mlflow.set_tag("quality_gate_passed", str(_passes_gate(quality)).lower())
    print(f"logged to MLflow experiment {EXPERIMENT}")


def _passes_gate(quality: dict) -> bool:
    gate = load_params("quality_gate")
    return (
        quality["detection_rate"] is not None
        and quality["detection_rate"] >= gate["min_detection_rate"]
        and quality["false_alarm_rate"] <= gate["max_false_alarm_rate"]
    )


if __name__ == "__main__":
    main()
