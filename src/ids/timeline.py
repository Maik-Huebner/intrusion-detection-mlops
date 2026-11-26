"""Draw the live demo as a timeline from the metrics Prometheus recorded.

Three panels over the last minutes: flows per second by verdict, the share of drifted features with
the alert threshold, and the model version the API served. Used for the README and the slides; the
interactive version is the Grafana dashboard.

Usage::

    uv run python -m ids.timeline --minutes 20 --output docs/images/live_demo.png
"""

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("agg")

import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

from ids import web
from ids.config import load_params  # noqa: E402

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")
BENIGN, ATTACK, DRIFT, MODEL = "#3b9a5b", "#d1495b", "#e08a1e", "#2a7ab8"


def query_range(expr: str, start: float, end: float, step: int = 5) -> list[dict]:
    params = urllib.parse.urlencode({"query": expr, "start": start, "end": end, "step": step})
    with web.urlopen(f"{PROMETHEUS_URL}/api/v1/query_range?{params}", timeout=30) as response:
        return json.load(response)["data"]["result"]


def _series(result: dict) -> tuple[list[datetime], list[float]]:
    return [datetime.fromtimestamp(t) for t, _ in result["values"]], [float(v) for _, v in result["values"]]


def _segments(result: dict, gap: float = 15) -> list[list[datetime]]:
    """Split a series where Prometheus had no samples for more than ``gap`` seconds."""
    times = [float(ts) for ts, _ in result["values"]]
    segments, current = [], [times[0]]
    for previous, ts in zip(times, times[1:], strict=False):
        if ts - previous > gap:
            segments.append(current)
            current = []
        current.append(ts)
    segments.append(current)
    return [[datetime.fromtimestamp(ts) for ts in seg] for seg in segments]


def _visible_from(scenes_file: Path) -> float:
    scenes = json.loads(scenes_file.read_text(encoding="utf-8"))
    return scenes[1]["time"] - 6 if len(scenes) > 2 else scenes[0]["time"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--minutes", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("docs/images/live_demo.png"))
    parser.add_argument("--scenes", type=Path, help="JSON with scene start times (written by ids.demo)")
    args = parser.parse_args()

    end = time.time()
    start = end - 60 * args.minutes
    threshold = load_params("drift")["share_threshold"]

    fig, (ax_flows, ax_drift, ax_model) = plt.subplots(
        3, 1, figsize=(11, 6.6), sharex=True, gridspec_kw={"height_ratios": [3, 2.2, 1]}
    )
    series = {r["metric"]["verdict"]: _series(r) for r in query_range(
        "sum by (verdict) (rate(ids_flows_scored_total[15s]))", start, end)}  # fmt: skip
    if {"attack", "benign"} <= series.keys() and series["attack"][0] == series["benign"][0]:
        x = series["attack"][0]
        ax_flows.stackplot(x, series["attack"][1], series["benign"][1], colors=[ATTACK, BENIGN], alpha=0.75,
                           labels=["model says: attack", "model says: benign"])  # fmt: skip
    ax_flows.set_ylabel("flows / s")
    ax_flows.legend(loc="upper left", bbox_to_anchor=(1.0, 1.0), fontsize=9, frameon=False)
    ax_flows.set_title(
        "Live demo: replayed traffic, drift monitor and rollout (measured by Prometheus)", fontsize=11, pad=34
    )

    for result in query_range("ids_drift_share", start, end):
        x, y = _series(result)
        ax_drift.fill_between(x, y, color=DRIFT, alpha=0.3, linewidth=0)
        ax_drift.plot(x, y, color=DRIFT, linewidth=1.8)
    ax_drift.axhline(threshold, color=ATTACK, linestyle="--", linewidth=1)
    label = f" alert threshold {threshold:.0%}"
    ax_drift.text(1.0, threshold, label, transform=ax_drift.get_yaxis_transform(), color=ATTACK, fontsize=8)
    ax_drift.set_ylabel("drifted\nfeatures")
    ax_drift.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax_drift.set_ylim(0, max(0.4, ax_drift.get_ylim()[1]))

    colours = iter(["#7f9fbf", MODEL, "#1d4f7a", "#9db9d6"])
    for result in sorted(query_range("ids_model_info", start, end), key=lambda r: r["values"][0][0]):
        version = result["metric"].get("version", "?")
        label = "baked-in model" if version == "file" else f"model v{version}"
        colour = next(colours, MODEL)
        for x in _segments(result):  # a version can be served twice (rollback): one bar per period
            if args.scenes:
                x = [ts for ts in x if ts.timestamp() >= _visible_from(args.scenes)] or x
            ax_model.plot(x, [0] * len(x), color=colour, linewidth=10, solid_capstyle="butt")
            ax_model.text(x[len(x) // 2], 0.45, label, ha="center", fontsize=9, color=colour, weight="bold",
                          clip_on=True)  # fmt: skip
    ax_model.set_ylim(-0.6, 1)
    ax_model.set_yticks([])
    ax_model.set_ylabel("served")
    ax_model.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))

    if args.scenes:
        scenes = json.loads(args.scenes.read_text(encoding="utf-8"))[:-1]  # last entry marks the end
        # Start shortly before the first traffic scene: before that the API restarts (rollback) and still
        # shows the state of whatever ran earlier.
        left = _visible_from(args.scenes)
        visible = [s for s in scenes if s["time"] >= left]
        for i, scene in enumerate(visible):
            when = datetime.fromtimestamp(scene["time"])
            for ax in (ax_flows, ax_drift, ax_model):
                ax.axvline(when, color="#888888", linewidth=0.8, linestyle=":")
            y = 1.0 + 0.09 * (i % 2)  # alternate heights so neighbouring labels do not overlap
            ax_flows.text(when, y, " " + scene["label"], transform=ax_flows.get_xaxis_transform(), fontsize=8,
                          va="bottom", color="#333333")  # fmt: skip
        for ax in (ax_flows, ax_drift, ax_model):
            ax.set_xlim(left=datetime.fromtimestamp(left))

    for ax in (ax_flows, ax_drift, ax_model):
        ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=180)
    print(f"saved {args.output}")


if __name__ == "__main__":
    main()
