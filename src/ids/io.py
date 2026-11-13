"""Small I/O helpers shared by the pipeline stages."""

import json
from pathlib import Path
from typing import Any


def write_json(path: Path, data: Any) -> None:
    """Write pretty, stable JSON (sorted keys keep diffs and DVC hashes deterministic)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
