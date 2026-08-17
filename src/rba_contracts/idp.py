"""IdP (PEP) login / MFA / session contracts.

Thesis core is RBA (ADR-0015); this API is the Auth0/Authentik-shaped shell
(ADR-0014), not an OIDC/SAML IdP. Identity lives here, not on the PDP.
`rba-idp` implements these; `decision-service` keeps `POST /risk/evaluate`.
Optional risk/session fields stay unset until later IdP stages (ADR-0013).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from rba_contracts.enums import Action, RiskLevel
from rba_contracts.evaluate import Reason


class LoginOutcome(str, Enum):
    """What the IdP tells the client after credentials (and later, after the PDP).

    ``ACCESS_DENIED`` is IdP-7 authz (no group grant), not a PDP ``BLOCK``.
    """

    AUTHENTICATED = "AUTHENTICATED"
    MFA_REQUIRED = "MFA_REQUIRED"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    BLOCKED = "BLOCKED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    ACCESS_DENIED = "ACCESS_DENIED"


def outcome_from_action(action: Action) -> LoginOutcome:
    """Map a PDP enforcement action to an IdP login outcome."""
    return {
        Action.ALLOW: LoginOutcome.AUTHENTICATED,
        Action.REQUIRE_MFA: LoginOutcome.MFA_REQUIRED,
        Action.REAUTHENTICATE: LoginOutcome.REAUTH_REQUIRED,
        Action.BLOCK: LoginOutcome.BLOCKED,
    }[action]


class LoginRequest(BaseModel):
    """POST /login. Password never appears on any response."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    password: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    ip_address: str = Field(min_length=1)
    asn: str | None = None
    country: str | None = None
    device_type: str | None = None
    os: str | None = None
    browser: str | None = None
    user_agent: str | None = None
    redirect_uri: str | None = Field(
        default=None,
        min_length=1,
        description="Registered client callback (Demo-2). Not OIDC.",
    )


class SessionToken(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1)
    expires_at: datetime


class LoginResponse(BaseModel):
    """POST /login and POST /mfa/verify.

    IdP-2 may return only ``outcome`` (+ ``user_id`` on success). Risk fields
    appear at IdP-3; ``session`` / ``challenge_id`` at IdP-4.
    """

    model_config = ConfigDict(extra="forbid")

    outcome: LoginOutcome
    user_id: str | None = None
    event_id: UUID | None = None
    action: Action | None = None
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    risk_level: RiskLevel | None = None
    reasons: list[Reason] = Field(default_factory=list)
    session: SessionToken | None = None
    challenge_id: UUID | None = None
    detail: str | None = None
    redirect_to: str | None = Field(
        default=None,
        description="Full callback URL with one-time code when the app has a redirect_uri.",
    )


class MfaVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: UUID
    code: str = Field(min_length=1)
    redirect_uri: str | None = Field(default=None, min_length=1)


class CallbackTokenRequest(BaseModel):
    """POST /callback/token — relying party exchanges a one-time code (ADR-0024)."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)


class UserPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1)
    email: str = Field(min_length=1)
    created_at: datetime
    is_admin: bool = False


class CallbackTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session: SessionToken
    user: UserPublic


class SessionResponse(BaseModel):
    """GET /session when a valid token is presented."""

    model_config = ConfigDict(extra="forbid")

    user: UserPublic
    expires_at: datetime
