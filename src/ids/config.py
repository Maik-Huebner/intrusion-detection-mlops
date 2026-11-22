"""Project paths and parameter loading.

All paths are relative to the repository root, which is where DVC runs every stage.
"""

from pathlib import Path
from typing import Any

import yaml

PARAMS_FILE = Path("params.yaml")

RAW_ARCHIVE = Path("data/raw/CICIDS2017_improved.zip")
INTERIM_DIR = Path("data/interim")
PREPARED_DIR = Path("data/prepared")
MODEL_FILE = Path("models/model.joblib")
REFERENCE_PROFILE = Path("models/reference_profile.json")  # drift reference, shipped with the model
METRICS_FILE = Path("metrics.json")
REPORTS_DIR = Path("reports")


def load_params(section: str | None = None) -> dict[str, Any]:
    """Return ``params.yaml`` or one of its top-level sections."""
    params = yaml.safe_load(PARAMS_FILE.read_text(encoding="utf-8"))
    return params if section is None else params[section]
