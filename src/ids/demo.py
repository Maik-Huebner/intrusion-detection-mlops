"""The whole drift story as one reproducible live demo against the running compose stack.

1. Roll back: the old model (trained Monday-Wednesday) is @champion, the API restarts with it.
2. Wednesday traffic: known attacks are caught, the drift monitor stays calm.
3. Thursday traffic: unseen attacks - no alarms at all, but the drift monitor fires (IdsDataDrift).
4. Rollout: the retrained model (Monday-Thursday) becomes @champion, the API restarts with it.
5. Friday traffic: attacks the new model has never seen either are caught again.

Afterwards ``ids.timeline`` draws what Prometheus measured, with the scenes marked.

Usage (stack running, both model versions registered)::

    uv run python -m ids.demo --before 1 --after 2
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from ids import replay, timeline
from ids.registry import set_champion

SCENES_FILE = Path("docs/images/live_demo_scenes.json")


def _rollout(version: str) -> None:
    set_champion(version)
    subprocess.run(["docker", "compose", "--env-file", "local.env", "restart", "api"], check=True)
    for _ in range(60):  # wait until the API answers again with the new version
        try:
            with urllib.request.urlopen(f"{replay.API_URL}/model", timeout=2) as response:
                if json.load(response)["version"] == version:
                    return
        except OSError:
            pass
        time.sleep(1)
    sys.exit(f"API did not come back with model version {version}")


def _replay(day: str, flows: int, rate: int) -> None:
    sys.argv = ["replay", day, "--flows", str(flows), "--rate", str(rate)]
    replay.main()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--before", required=True, help="registry version trained on Monday-Wednesday")
    parser.add_argument("--after", required=True, help="registry version retrained with Thursday")
    parser.add_argument("--flows", type=int, default=30_000, help="flows per scene")
    parser.add_argument("--rate", type=int, default=1000, help="flows per second")
    args = parser.parse_args()

    scenes = []

    def scene(label: str) -> None:
        scenes.append({"time": time.time(), "label": label})
        print(f"\n=== {label} ===")

    scene(f"rollback to v{args.before}")
    _rollout(args.before)
    scene("Wednesday: known attacks")
    _replay("wednesday", args.flows, args.rate)
    scene("Thursday: unseen attacks")
    _replay("thursday", args.flows, args.rate)
    print("waiting 40 s so Prometheus can fire the IdsDataDrift alert ...")
    time.sleep(40)
    scene(f"retrained v{args.after} rolled out")
    _rollout(args.after)
    scene("Friday: never seen by either model")
    _replay("friday", args.flows, args.rate)
    scenes.append({"time": time.time(), "label": "end"})

    SCENES_FILE.parent.mkdir(parents=True, exist_ok=True)
    SCENES_FILE.write_text(json.dumps(scenes, indent=2) + "\n", encoding="utf-8")
    minutes = int((scenes[-1]["time"] - scenes[0]["time"]) / 60) + 2
    sys.argv = ["timeline", "--minutes", str(minutes), "--scenes", str(SCENES_FILE)]
    timeline.main()


if __name__ == "__main__":
    main()
