"""Async bus payloads (transactional outbox → RabbitMQ)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from rba_contracts.enums import Action, RiskLevel
from rba_contracts.evaluate import Reason
from rba_contracts.features import FeatureVectorV1

DECISION_MADE_CHANNEL = "rba.decision.made.v1"


class DecisionMadeEvent(BaseModel):
    """Outbox / bus payload. Consumers MUST be idempotent on event_id."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    occurred_at: datetime
    application_id: str
    user_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    action: Action
    model_version: str
    policy_version: str
    feature_schema_version: str
    fallback: bool = False
    reasons: list[Reason] = Field(default_factory=list)
    features: FeatureVectorV1 | None = None
