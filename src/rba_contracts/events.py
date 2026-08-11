"""Async bus payloads (transactional outbox → RabbitMQ)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from rba_contracts.enums import Action, RiskLevel
from rba_contracts.evaluate import Reason
from rba_contracts.features import FeatureVectorV1

DECISION_MADE_CHANNEL = "rba.decision.made.v1"


class LoginEventSnapshot(BaseModel):
    """Raw login signals needed by profile-service to call update_profile.

    Optional on DecisionMadeEvent for backward compatibility with Phase 2/3
    payloads; Phase 4+ publishers SHOULD always set it.
    """

    model_config = ConfigDict(extra="forbid")

    login_timestamp: datetime
    ip_address: str = Field(min_length=1)
    asn: str | None = None
    country: str | None = None
    device_type: str | None = None
    os: str | None = None
    browser: str | None = None
    login_successful: bool = True

    def to_feature_event(self) -> dict[str, object]:
        return {
            "login_timestamp": self.login_timestamp,
            "ip_address": self.ip_address,
            "asn": self.asn,
            "country": self.country,
            "device_type": self.device_type,
            "os": self.os,
            "browser": self.browser,
            "login_successful": self.login_successful,
        }


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
    login: LoginEventSnapshot | None = None
