"""Versioned RBA contracts (feature schema, model I/O, PDP API, events, policy)."""

from rba_contracts.enums import Action, RiskLevel
from rba_contracts.evaluate import Reason, RiskEvaluateRequest, RiskEvaluateResponse
from rba_contracts.events import DECISION_MADE_CHANNEL, DecisionMadeEvent, LoginEventSnapshot
from rba_contracts.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FeatureVectorV1
from rba_contracts.model import (
    FREEMAN_FEATURES,
    ModelArtifactMetadata,
    ModelPrediction,
    SignalContribution,
)
from rba_contracts.policy import PolicyConfig, apply_policy

__all__ = [
    "DECISION_MADE_CHANNEL",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FREEMAN_FEATURES",
    "Action",
    "DecisionMadeEvent",
    "FeatureVectorV1",
    "LoginEventSnapshot",
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

__version__ = "0.1.1"
