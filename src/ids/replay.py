"""Replay real traffic of one capture day against the running API - the live demo of the drift story.

The API only sees the features. The replay knows the labels, so it can tell how many attacks the model
really caught - the number a SOC only learns days later, after analysts have confirmed incidents.

Usage::

    uv run python -m ids.replay wednesday              # known attack types: alarms, no drift
    uv run python -m ids.replay thursday               # unseen attacks: no alarms, but drift
    uv run python -m ids.replay friday --flows 30000 --rate 1000

Flows are sampled at random (fixed seed) from ``data/interim/<day>.parquet`` (stage ``prepare``).
"""

import argparse
import json
import os
import time
import urllib.request

import numpy as np
import pandas as pd

from ids import schema, web
from ids.config import INTERIM_DIR

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")


def _post(path: str, body: dict) -> dict:
    request = urllib.request.Request(  # noqa: S310 - opened with web.urlopen
        f"{API_URL}{path}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with web.urlopen(request, timeout=30) as response:
        return json.load(response)


def _get(path: str) -> dict:
    with web.urlopen(f"{API_URL}{path}", timeout=10) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay one capture day against the scoring API")
    parser.add_argument("day", choices=schema.DAYS)
    parser.add_argument("--flows", type=int, default=20_000, help="number of flows to send")
    parser.add_argument("--batch", type=int, default=250, help="flows per /predict/batch request")
    parser.add_argument("--rate", type=float, default=500, help="flows per second (0 = as fast as possible)")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    df = pd.read_parquet(INTERIM_DIR / f"{args.day}.parquet")
    df = df.sample(min(args.flows, len(df)), random_state=args.seed).reset_index(drop=True)
    model = _get("/model")
    print(
        f"replaying {len(df):,} {args.day} flows to {API_URL} (model {model['source']}, v{model['version']})"
    )

    y_true, y_pred = [], []
    start = time.monotonic()
    for i in range(0, len(df), args.batch):
        part = df.iloc[i : i + args.batch]
        flows = part[schema.FEATURES].astype(float).to_dict("records")
        answer = _post("/predict/batch", {"flows": flows})
        y_true += part[schema.TARGET].tolist()
        y_pred += [p["is_attack"] for p in answer["predictions"]]
        if args.rate:  # pace the traffic so Prometheus sees a steady stream
            time.sleep(max(0.0, (i + len(part)) / args.rate - (time.monotonic() - start)))
        if (i // args.batch) % 20 == 0:
            print(f"  {i + len(part):>7,} flows sent, {sum(y_pred):>6,} alarms", flush=True)

    t, p = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    attacks, benign = int(t.sum()), int((~t).sum())
    print(f"\n{len(t):,} flows: {attacks:,} attacks, {benign:,} benign  ({time.monotonic() - start:.0f} s)")
    if attacks:
        caught = int((t & p).sum())
        print(f"detection rate   {caught / attacks:7.2%}  ({caught:,} of {attacks:,} attacks caught)")
        for label, group in df[t].groupby(schema.LABEL):
            print(f"    {label:<28} {p[group.index].mean():7.2%}  (n={len(group):,})")
    if benign:
        print(f"false alarm rate {(~t & p).sum() / benign:7.2%}  ({int((~t & p).sum()):,} false alarms)")
    try:
        drift = _get("/drift")
        print(f"drift monitor    drift={drift['drift']}  share={drift['drift_share']}  "
              f"top: {', '.join(list(drift['top_features'])[:3])}")  # fmt: skip
    except urllib.error.HTTPError:
        print("drift monitor    off (no reference profile)")


if __name__ == "__main__":
    main()
