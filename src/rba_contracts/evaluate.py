"""POST /risk/evaluate request and response models (PDP API)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from rba_contracts.enums import Action, RiskLevel


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    signal: str = Field(min_length=1)
    contribution: float | None = None
    detail: str | None = None


class RiskEvaluateRequest(BaseModel):
    """Signals accepted by the PDP. Field names match rba-features canonical event keys."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    application_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    timestamp: datetime
    ip_address: str = Field(min_length=1)
    asn: str | None = None
    country: str | None = None
    device_type: str | None = None
    os: str | None = None
    browser: str | None = None
    login_successful: bool = True
    user_agent: str | None = None
    device_id: str | None = None

    def to_feature_event(self) -> dict[str, object]:
        """Map to the dict shape expected by rba_features.compute_features."""
        return {
            "login_timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "asn": self.asn,
            "country": self.country,
            "device_type": self.device_type,
            "os": self.os,
            "browser": self.browser,
            "login_successful": self.login_successful,
        }


class RiskEvaluateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    action: Action
    reasons: list[Reason] = Field(default_factory=list)
    model_version: str
    policy_version: str
    feature_schema_version: str
    fallback: bool = False
    scored_at: datetime
    # Monitor-only mode (RF-09): the action the engine decided but did NOT
    # enforce. When set, `action` is always ALLOW and the PEP must let the
    # login through — the engine's opinion is recorded, not applied.
    monitored_action: Action | None = None
