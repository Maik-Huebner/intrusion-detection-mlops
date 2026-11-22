"""Evaluate the analyst notes of the running API: how often does the LLM pass every rule?

Sends attack flows of every known type from the test set to ``/explain`` and measures

* the rule pass rate (share of notes that come from the LLM, not from the template)
* which rule fails how often, and why the template was used (rules, timeout, ...)
* the LLM latency (p50, p95)

Result: ``reports/llm_evaluation.json`` (with example notes) and a run in MLflow
(experiment ``ids-llm-evaluation``), so prompt versions can be compared like model versions.

Usage (stack running, ``make llm`` done)::

    MLFLOW_TRACKING_URI=http://127.0.0.1:5050 uv run python -m ids.evaluate_llm --per-type 4
"""

import argparse
import json
import os
import statistics
import time
import urllib.request
from collections import Counter

import pandas as pd

from ids import schema
from ids.config import PREPARED_DIR, REPORTS_DIR
from ids.io import write_json

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
EXPERIMENT = "ids-llm-evaluation"


def _explain(flow: dict) -> dict:
    request = urllib.request.Request(
        f"{API_URL}/explain", data=json.dumps(flow).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--per-type", type=int, default=4, help="attack flows per attack type")
    args = parser.parse_args()

    test = pd.read_parquet(PREPARED_DIR / "test.parquet")
    attacks = test[test[schema.TARGET] == 1]
    sample = attacks.groupby(schema.LABEL, group_keys=False).apply(
        lambda g: g.sample(min(args.per_type, len(g)), random_state=0)
    )
    results, start = [], time.perf_counter()
    for _, row in sample.iterrows():
        answer = _explain(row[schema.FEATURES].astype(float).to_dict())
        results.append({"true_type": row[schema.LABEL], **answer})
        print(f"{row[schema.LABEL]:<18} -> {answer['source']:<8} {answer.get('reason') or ''}")

    explained = [r for r in results if r["source"] != "no_alarm"]
    from_llm = [r for r in explained if r["source"] == "llm"]
    seconds = [r["seconds"] for r in explained if r.get("seconds")]
    failed_rules = Counter(rule for r in explained for rule, ok in r.get("rules", {}).items() if not ok)
    reasons = Counter(r.get("reason") for r in explained if r["source"] == "fallback")
    llm_model = next((r["llm_model"] for r in explained if r.get("llm_model")), "none")
    result = {
        "llm_model": llm_model,
        "prompt_version": next((r["prompt_version"] for r in from_llm), "v1"),
        "flows": len(results),
        "explained": len(explained),
        "rule_pass_rate": round(len(from_llm) / len(explained), 4) if explained else None,
        "type_correct_rate": round(
            sum(r["prediction"]["attack_type"] == r["true_type"] for r in explained) / len(explained), 4
        )
        if explained
        else None,  # fmt: skip
        "latency_p50_s": round(statistics.median(seconds), 2) if seconds else None,
        "latency_p95_s": round(statistics.quantiles(seconds, n=20)[-1], 2) if len(seconds) > 1 else None,
        "failed_rules": dict(failed_rules),
        "fallback_reasons": dict(reasons),
        "duration_s": round(time.perf_counter() - start),
        "examples": [
            {"type": r["true_type"], "source": r["source"], "note": r["note"]} for r in explained[:6]
        ],
    }
    write_json(REPORTS_DIR / "llm_evaluation.json", result)
    for key, value in result.items():
        if key not in ("examples", "prompt_version", "flows", "duration_s"):
            print(f"{key:<18} {value}")

    import mlflow

    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"{llm_model} prompt {result['prompt_version']}"):
        mlflow.log_params({"llm_model": llm_model, "prompt_version": result["prompt_version"],
                           "per_type": args.per_type})  # fmt: skip
        mlflow.log_metrics({k: v for k, v in result.items() if isinstance(v, int | float) and v is not None})
        mlflow.log_dict(result, "llm_evaluation.json")
    print(f"logged to MLflow experiment {EXPERIMENT}")


if __name__ == "__main__":
    main()
