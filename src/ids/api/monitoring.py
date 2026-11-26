"""Prometheus metrics of the scoring API, including the live drift monitor.

Prometheus scrapes ``GET /metrics`` every few seconds. Three groups of metrics:

* HTTP, the "golden signals": traffic, errors, latency
* model output: how many flows are scored, how many raise an alarm, how sure the model is
* data drift: PSI of the flows the model lets through against the reference profile
  (same method as the DVC stage ``drift``, see ``ids.drift``)
* LLM analyst notes: results, errors, latency, tokens
"""

import threading
from collections import deque

import numpy as np
import pandas as pd
from prometheus_client import Counter, Gauge, Histogram, Info

from ids.drift import psi, summarize

# --- HTTP ------------------------------------------------------------------------------------------
REQUESTS = Counter("ids_http_requests_total", "HTTP requests", ["path", "method", "status"])
LATENCY = Histogram(
    "ids_http_request_duration_seconds",
    "Request latency in seconds",
    ["path"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)

# --- Model output ----------------------------------------------------------------------------------
FLOWS = Counter("ids_flows_scored_total", "Scored flows by verdict", ["verdict"])  # benign | attack
PROBABILITY = Histogram(
    "ids_attack_probability",
    "Predicted probability of an attack",
    buckets=[0.01, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0],
)
MODEL = Info("ids_model", "The model the API serves")
ALARMS_BY_FAMILY = Counter("ids_alarms_by_family_total", "Alarms by predicted attack family", ["family"])

# --- LLM analyst notes -----------------------------------------------------------------------------
# result: ok | rejected (broke a rule) | error (timeout, unreachable, refusal) | budget | not_configured
LLM_REQUESTS = Counter("ids_llm_requests_total", "Analyst note requests by result", ["result"])
LLM_ERRORS = Counter("ids_llm_errors_total", "LLM errors by exception type", ["kind"])
LLM_LATENCY = Histogram(
    "ids_llm_latency_seconds", "LLM response time in seconds", buckets=[0.5, 1, 2, 5, 10, 20, 30, 60, 120]
)
LLM_TOKENS = Counter("ids_llm_tokens_total", "Tokens used by the LLM")

# --- Drift -----------------------------------------------------------------------------------------
DRIFT_SHARE = Gauge("ids_drift_share", "Share of drifted features in the recent 'benign' traffic")
DRIFT_DETECTED = Gauge("ids_drift_detected", "1 if the recent 'benign' traffic has drifted, else 0")
DRIFT_WINDOW = Gauge("ids_drift_window_flows", "Flows currently in the drift window")
FEATURE_PSI = Gauge("ids_feature_psi", "PSI of a feature in the drift window", ["feature"])


class DriftMonitor:
    """Sliding window over the most recent flows the model let through as benign.

    Every ``every`` new flows (once at least ``min_flows`` are in the window) the PSI against the
    reference profile is recomputed and published as gauges. Thread-safe: FastAPI runs synchronous
    endpoints in a thread pool.
    """

    def __init__(self, profile: dict, feature_threshold: float, share_threshold: float, window: int = 1000):
        self.profile = profile
        self.features = list(profile["features"])
        self.feature_threshold = feature_threshold
        self.share_threshold = share_threshold
        self.window: deque[np.ndarray] = deque(maxlen=window)
        self.min_flows = window // 2
        self.every = max(window // 10, 1)
        self._new = 0
        self._lock = threading.Lock()
        self.last: dict | None = None
        DRIFT_SHARE.set(0)
        DRIFT_DETECTED.set(0)
        DRIFT_WINDOW.set(0)

    def observe(self, passed: pd.DataFrame) -> None:
        """Add the flows that were scored as benign."""
        if passed.empty:
            return
        with self._lock:
            self.window.extend(passed[self.features].to_numpy(dtype=np.float64))
            self._new += len(passed)
            DRIFT_WINDOW.set(len(self.window))
            if len(self.window) >= self.min_flows and self._new >= self.every:
                self._new = 0
                self._publish()

    def _publish(self) -> None:
        recent = pd.DataFrame(np.vstack(self.window), columns=self.features)
        psis = psi(self.profile, recent)
        self.last = summarize(psis, self.feature_threshold, self.share_threshold)
        DRIFT_SHARE.set(self.last["drift_share"])
        DRIFT_DETECTED.set(int(self.last["drift"]))
        for feature, value in psis.items():
            FEATURE_PSI.labels(feature).set(round(value, 4))
