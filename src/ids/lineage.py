"""Lineage: which code, data and parameters produced a model?

Pure helpers without MLflow, so they are unit-tested and reused by the registry and the API.
"""

import subprocess
from pathlib import Path

import yaml

DVC_LOCK = Path("dvc.lock")


def flatten(data: dict, prefix: str = "") -> dict:
    """``{"test": {"f1": 0.9}}`` -> ``{"test.f1": 0.9}``. Lists become comma-separated strings."""
    flat = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{name}."))
        elif isinstance(value, list):
            flat[name] = ",".join(map(str, value))
        else:
            flat[name] = value
    return flat


def data_versions(lock_file: Path = DVC_LOCK) -> dict[str, str]:
    """MD5 hashes DVC recorded for the raw archive and the prepared train/test/future data."""
    stages = yaml.safe_load(lock_file.read_text(encoding="utf-8"))["stages"]
    versions = {}
    for stage, kind, path, key in (
        ("prepare", "deps", "data/raw/CICIDS2017_improved.zip", "data.raw_md5"),
        ("split", "outs", "data/prepared", "data.prepared_md5"),
    ):
        for entry in stages.get(stage, {}).get(kind, []):
            if entry["path"] == path:
                versions[key] = entry["md5"]
    return versions


def git_state() -> dict[str, str]:
    """Current commit and whether the working tree has uncommitted changes."""

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout.strip()  # noqa: S603, S607

    return {
        "git.commit": git("rev-parse", "HEAD") or "unknown",
        "git.dirty": str(bool(git("status", "--porcelain", "--untracked-files=no"))).lower(),
    }
