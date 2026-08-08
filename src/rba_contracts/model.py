"""Model I/O contract: predict_proba-compatible score + artifact metadata.

Primary scorer (Freeman) and supervised baselines both surface risk_score in
[0, 1] so the policy engine is model-agnostic. Freeman also exposes logrisk and
per-categorical LLR contributions.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Must stay identical to rba_ml_training.ml.models.freeman.FREEMAN_FEATURES.
FREEMAN_FEATURES: tuple[str, ...] = (
    "ip_address",
    "asn",
    "country",
    "device_type",
    "os",
    "browser",
    "hour",
)


class ModelFamily(str, Enum):
    FREEMAN = "freeman"
    LOGREG = "logreg"
    RANDOM_FOREST = "random_forest"
    LIGHTGBM = "lightgbm"
    XGBOOST = "xgboost"
    OTHER = "other"


class SignalContribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal: str = Field(min_length=1)
    contribution: float
    detail: str | None = None


class ModelPrediction(BaseModel):
    """Unified scorer output (the predict_proba contract)."""

    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    logrisk: float | None = None
    model_version: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    contributions: list[SignalContribution] = Field(default_factory=list)


class ProbaMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["identity", "logistic_logrisk", "platt", "isotonic", "other"]
    detail: str | None = None


class TrainWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: datetime
    end: datetime


class ModelArtifactMetadata(BaseModel):
    """JSON sidecar that accompanies every persisted model blob."""

    model_config = ConfigDict(extra="forbid")

    model_id: str
    model_version: str
    model_family: ModelFamily
    input_kind: Literal["freeman_categoricals", "feature_vector_v1"]
    feature_schema_version: str = "1.0.0"
    freeman_features: list[str] | None = None
    feature_names: list[str] | None = None
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    proba_mapping: ProbaMapping | None = None
    trained_at: datetime
    train_window: TrainWindow | None = None
    framework: str
    metrics: dict[str, Any] = Field(default_factory=dict)
