"""Request and response models of the API.

The flow model is generated from ``ids.schema.FEATURES``, so the API contract can never drift away
from the features the model was trained on. Field aliases keep the original CICFlowMeter names
(``"Flow Bytes/s"``), Python attribute names are snake_case.
"""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, create_model

from ids import schema

MAX_BATCH = 10_000


def attribute_name(feature: str) -> str:
    """``"Flow Bytes/s"`` -> ``"flow_bytes_s"``."""
    return re.sub(r"[^0-9a-z]+", "_", feature.lower()).strip("_")


def _field(feature: str) -> tuple[type, Any]:
    if feature == "Dst Port":
        return float, Field(alias=feature, ge=0, le=65535)
    if feature == "Protocol":
        return float, Field(alias=feature, description="0 = unknown, 1 = ICMP, 6 = TCP, 17 = UDP")
    if feature in schema.COUNTER_FEATURES:
        return float, Field(alias=feature, ge=0)
    return float, Field(alias=feature)


# A real SSH-Patator (brute force) flow from the test set, Tuesday. Used as the example in /docs.
# Only non-zero features are listed; the model scores it with P(attack) > 0.99.
EXAMPLE_FLOW: dict[str, float] = dict.fromkeys(schema.FEATURES, 0.0) | {
    "Dst Port": 22, "Protocol": 6, "Flow Duration": 11201640,
    "Total Fwd Packet": 22, "Total Bwd packets": 33,
    "Total Length of Fwd Packet": 2008, "Total Length of Bwd Packet": 2745,
    "Fwd Packet Length Max": 640, "Fwd Packet Length Mean": 91.2727, "Fwd Packet Length Std": 138.1821,
    "Bwd Packet Length Max": 976, "Bwd Packet Length Mean": 83.1818, "Bwd Packet Length Std": 217.2857,
    "Flow Bytes/s": 424.3129, "Flow Packets/s": 4.91,
    "Flow IAT Mean": 207437.7812, "Flow IAT Std": 570926.125, "Flow IAT Max": 2176167, "Flow IAT Min": 3,
    "Fwd IAT Total": 11201567, "Fwd IAT Mean": 533407.9375, "Fwd IAT Std": 860559.0625,
    "Fwd IAT Max": 2228519, "Fwd IAT Min": 260,
    "Bwd IAT Total": 11201510, "Bwd IAT Mean": 350047.1875, "Bwd IAT Std": 711216.3125,
    "Bwd IAT Max": 2176167, "Bwd IAT Min": 3,
    "Fwd PSH Flags": 16, "Bwd PSH Flags": 15, "Fwd Header Length": 712, "Bwd Header Length": 1064,
    "Fwd Packets/s": 1.964, "Bwd Packets/s": 2.946,
    "Packet Length Max": 976, "Packet Length Mean": 86.4182, "Packet Length Std": 188.2012,
    "Packet Length Variance": 35419.6914,
    "FIN Flag Count": 2, "SYN Flag Count": 2, "PSH Flag Count": 31, "ACK Flag Count": 54,
    "Down/Up Ratio": 1.5, "Average Packet Size": 86.4182,
    "Fwd Segment Size Avg": 91.2727, "Bwd Segment Size Avg": 83.1818,
    "Subflow Fwd Bytes": 36, "Subflow Bwd Bytes": 49,
    "FWD Init Win Bytes": 29200, "Bwd Init Win Bytes": 247, "Fwd Act Data Pkts": 16, "Fwd Seg Size Min": 32,
    "ICMP Code": -1, "ICMP Type": -1, "Total TCP Flow Time": 11201640,
}  # fmt: skip

Flow = create_model(
    "Flow",
    # NaN and infinity are rejected: CICFlowMeter writes them for broken flows, the model never saw them.
    __config__=ConfigDict(
        populate_by_name=True, allow_inf_nan=False, json_schema_extra={"examples": [EXAMPLE_FLOW]}
    ),
    __doc__="Behavioural features of one network flow, as computed by CICFlowMeter.",
    **{attribute_name(f): _field(f) for f in schema.FEATURES},
)


class Prediction(BaseModel):
    is_attack: bool = Field(description="True if the attack probability reaches the alarm threshold")
    attack_probability: float = Field(ge=0, le=1)
    attack_type: str | None = Field(
        default=None,
        description="Only for alarms: e.g. 'SSH-Patator', or 'uncertain' below the confidence floor",
    )
    family: str | None = Field(default=None, description="Only for alarms: attack family, e.g. 'Brute Force'")
    type_confidence: float | None = Field(default=None, ge=0, le=1)


class BatchRequest(BaseModel):
    flows: list[Flow] = Field(min_length=1, max_length=MAX_BATCH)  # type: ignore[valid-type]


class BatchResponse(BaseModel):
    predictions: list[Prediction]
    alarms: int


class ModelInfo(BaseModel):
    source: str = Field(description="Where the model was loaded from (file path or MLflow model URI)")
    version: str = Field(description="Registry version, or 'file' for the model baked into the image")
    revision: str = Field(description="Git commit the image was built from ('dev' outside the CD pipeline)")
    fallback: bool = Field(description="True if MODEL_URI could not be loaded and the baked-in model serves")
    threshold: float
    features: int
    drift_monitoring: bool = Field(description="True if a reference profile for drift monitoring is loaded")


class DriftStatus(BaseModel):
    window_flows: int = Field(description="Flows scored as benign in the sliding window")
    drift: bool | None = Field(description="None until the window holds enough flows")
    drift_share: float | None = None
    drifted_features: int | None = None
    top_features: dict[str, float] = {}


class UnusualFeature(BaseModel):
    feature: str
    value: float
    normal_low: float = Field(description="10 % quantile of benign training traffic")
    normal_high: float = Field(description="90 % quantile of benign training traffic")
    distance: float = Field(description="How far outside the normal range, in multiples of its width")


class Explanation(BaseModel):
    """Response of /explain: the models' findings plus a note for the analyst."""

    prediction: Prediction
    unusual_features: list[UnusualFeature]
    drift_warning: bool = Field(description="True if the live drift monitor currently reports drift")
    note: str
    source: str = Field(description="'llm', 'fallback' (template, see reason) or 'no_alarm'")
    reason: str | None = Field(default=None, description="Why the template was used, e.g. 'rules', 'timeout'")
    rules: dict[str, bool] = Field(default={}, description="Rule check of the LLM note")
    llm_model: str | None = None
    prompt_version: str | None = None
    seconds: float | None = None
