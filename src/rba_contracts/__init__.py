"""Versioned RBA contracts (feature schema, model I/O, PDP API, IdP API, events, policy)."""

from rba_contracts.admin import (
    AdminUserPublic,
    ApplicationPublic,
    CreateApplicationRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    PatchApplicationRequest,
    PatchUserRequest,
)
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
from rba_contracts.idp import (
    LoginOutcome,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    SessionResponse,
    SessionToken,
    UserPublic,
    outcome_from_action,
)
from rba_contracts.policy import PolicyConfig, apply_policy

__all__ = [
    "DECISION_MADE_CHANNEL",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "FREEMAN_FEATURES",
    "Action",
    "AdminUserPublic",
    "ApplicationPublic",
    "CreateApplicationRequest",
    "CreateUserRequest",
    "DecisionListResponse",
    "DecisionMadeEvent",
    "DecisionRecord",
    "FeatureVectorV1",
    "LoginEventSnapshot",
    "ModelArtifactMetadata",
    "ModelPrediction",
    "LoginOutcome",
    "LoginRequest",
    "LoginResponse",
    "MfaVerifyRequest",
    "PatchApplicationRequest",
    "PatchUserRequest",
    "PolicyConfig",
    "Reason",
    "RiskEvaluateRequest",
    "RiskEvaluateResponse",
    "RiskLevel",
    "SessionResponse",
    "SessionToken",
    "SignalContribution",
    "UserPublic",
    "apply_policy",
    "outcome_from_action",
]

__version__ = "0.3.0"
