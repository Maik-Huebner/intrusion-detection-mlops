"""Ask the running API for an analyst note on one real flow - for the live demo.

Usage::

    uv run python -m ids.note friday DDoS           # a DDoS flow (unknown to the Mon-Wed model)
    uv run python -m ids.note tuesday SSH-Patator   # a known attack type

The flow is drawn at random (fixed seed) from ``data/interim/<day>.parquet``. The true label is shown
next to what the models say, so the audience can see when the attack type model is wrong.
"""

import argparse
import json
import textwrap
import urllib.request

import pandas as pd

from ids import schema, web
from ids.config import INTERIM_DIR
from ids.replay import API_URL


def flow_of(day: str, label: str, seed: int = 1) -> dict:
    flows = pd.read_parquet(INTERIM_DIR / f"{day}.parquet")
    match = flows[flows[schema.LABEL] == label]
    if match.empty:
        raise SystemExit(
            f"no {label!r} flows on {day}; labels: {', '.join(sorted(flows[schema.LABEL].unique()))}"
        )
    return match.sample(1, random_state=seed)[schema.FEATURES].astype(float).iloc[0].to_dict()


def explain(flow: dict) -> dict:
    request = urllib.request.Request(  # noqa: S310 - opened with web.urlopen
        f"{API_URL}/explain", data=json.dumps(flow).encode(), headers={"Content-Type": "application/json"}
    )
    with web.urlopen(request, timeout=180) as response:
        return json.load(response)


def show(label: str, answer: dict) -> None:
    p = answer["prediction"]
    if p["is_attack"]:
        verdict = f"{p['attack_type']} ({p['family']}, {p['type_confidence']:.1%} sure)"
    else:
        verdict = "benign"
    print(f"true label     {label}")
    print(f"models say     {verdict}, attack probability {p['attack_probability']:.1%}")
    print(f"drift warning  {answer['drift_warning']}")
    source = answer["source"] + (f" ({answer['reason']})" if answer.get("reason") else "")
    seconds = f", {answer['seconds']} s" if answer.get("seconds") else ""
    print(f"note from      {source}{seconds}")
    print(textwrap.indent(textwrap.fill(answer["note"], 100), "  "))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("day", choices=schema.DAYS)
    parser.add_argument("label", help="e.g. DDoS, SSH-Patator, 'DoS Hulk', BENIGN")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    show(args.label, explain(flow_of(args.day, args.label, args.seed)))


if __name__ == "__main__":
    main()
