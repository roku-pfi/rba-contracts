"""Async bus payloads (transactional outbox → RabbitMQ)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from rba_contracts.enums import Action, EngineMode, RiskLevel
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
    tenant_id: str = Field(min_length=1)
    application_id: str
    user_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    action: Action
    enforced_action: Action
    engine_mode: EngineMode
    simulated: bool = False
    model_version: str
    policy_version: str
    feature_schema_version: str
    fallback: bool = False
    reasons: list[Reason] = Field(default_factory=list)
    features: FeatureVectorV1 | None = None
    login: LoginEventSnapshot | None = None


LOGIN_CONFIRMED_CHANNEL = "rba.login.confirmed.v1"


class LoginConfirmRequest(BaseModel):
    """IdP → PDP (`POST /risk/confirm`): the step-up of this decision was passed."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID = Field(description="The decision's event_id, from /risk/evaluate.")
    tenant_id: str = Field(min_length=1)


class LoginConfirmResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    # False when the decision did not wait for a step-up (ALLOW was learned at
    # once; BLOCK and failed passwords are never learned) or was already confirmed.
    confirmed: bool


class LoginConfirmedEvent(BaseModel):
    """A challenged login was completed: the user passed the step-up.

    The profile learns a login's context only from a login that ended in a
    session: at once for an enforced ALLOW, on this event for a step-up. A
    step-up nobody passes (an attacker with the password but not the passkey)
    teaches the profile nothing. Consumers MUST be idempotent on event_id.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: UUID = Field(description="This event's id: uuid5 of the decision, so one per decision.")
    decision_event_id: UUID
    occurred_at: datetime
    tenant_id: str = Field(min_length=1)
    application_id: str
    user_id: str
    login: LoginEventSnapshot
