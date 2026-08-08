"""Versioned RBA contracts (feature schema, model I/O, PDP API, events, policy)."""

from rba_contracts.enums import Action, RiskLevel
from rba_contracts.evaluate import Reason, RiskEvaluateRequest, RiskEvaluateResponse
from rba_contracts.events import DecisionMadeEvent
from rba_contracts.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FeatureVectorV1
from rba_contracts.model import (
    FREEMAN_FEATURES,
    ModelArtifactMetadata,
    ModelPrediction,
    SignalContribution,
)
from rba_contracts.policy import PolicyConfig, apply_policy

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FREEMAN_FEATURES",
    "Action",
    "DecisionMadeEvent",
    "FeatureVectorV1",
    "ModelArtifactMetadata",
    "ModelPrediction",
    "PolicyConfig",
    "Reason",
    "RiskEvaluateRequest",
    "RiskEvaluateResponse",
    "RiskLevel",
    "SignalContribution",
    "apply_policy",
]

__version__ = "0.1.0"
