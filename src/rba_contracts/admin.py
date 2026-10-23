"""Admin console contracts (tenants, users, applications, groups, roles, decisions).

Policy GET/PUT reuses ``TenantPolicy``. Identity CRUD is served by ``rba-idp``;
the decision list is the audit-service read model.

**Tenancy (ADR-0033).** Every directory object belongs to exactly one tenant.
Create requests carry no ``tenant_id``: the tenant comes from the operator's
session (or, for a platform operator, from the tenant they switched to), never
from the request body.

**RBAC (ADR-0029).** The chain is
``user → group → role → permission(resource, operation)``, every role scoped to
one application. Groups answer *who*; roles answer *what you may do*. A group
holding any role on an application is what grants sign-in to it — there is no
separate ``access`` grant any more.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rba_contracts.enums import Action, EngineMode, RiskLevel
from rba_contracts.evaluate import Reason
from rba_contracts.events import LoginEventSnapshot
from rba_contracts.features import FeatureVectorV1


# ---------------------------------------------------------------- tenants

HEX_COLOUR = r"^#[0-9A-Fa-f]{6}$"
# Lowercase DNS name with at least one dot: "rokubank.example".
EMAIL_DOMAIN = r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
TENANT_ID = r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$"


class TenantBranding(BaseModel):
    """How the hosted login looks for this tenant's applications (ADR-0036).

    ``rokusec``: RokuSec's own login ("Continuá a Kaze Labs").
    ``tenant``: the tenant's name, logo and colours, with a small
    "Protegido por RokuSec" seal. Either way the page is served by the IdP.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=128)
    login_style: Literal["rokusec", "tenant"] = "rokusec"
    logo_url: str | None = Field(default=None, max_length=512)
    primary_colour: str = Field(default="#1466E5", pattern=HEX_COLOUR)
    accent_colour: str = Field(default="#152953", pattern=HEX_COLOUR)


class TenantPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=TENANT_ID)
    name: str = Field(min_length=1, max_length=128)
    # Console sign-in is routed by these (home realm discovery). A domain
    # belongs to one tenant across the platform.
    operator_domains: list[str] = Field(default_factory=list)
    branding: TenantBranding
    # The platform tenant (RokuSec itself): its operators may switch tenants.
    is_platform: bool = False
    created_at: datetime


class CreateTenantRequest(BaseModel):
    """Platform operators only."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=TENANT_ID)
    name: str = Field(min_length=1, max_length=128)
    operator_domains: list[str] = Field(default_factory=list)
    branding: TenantBranding | None = None

    @model_validator(mode="after")
    def _domains(self) -> CreateTenantRequest:
        _check_domains(self.operator_domains)
        return self


class PatchTenantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=128)
    operator_domains: list[str] | None = None
    branding: TenantBranding | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> PatchTenantRequest:
        if self.name is None and self.operator_domains is None and self.branding is None:
            raise ValueError("at least one field is required")
        if self.operator_domains is not None:
            _check_domains(self.operator_domains)
        return self


def _check_domains(domains: list[str]) -> None:
    import re

    for d in domains:
        if not re.fullmatch(EMAIL_DOMAIN, d):
            raise ValueError(f"not a lowercase email domain: {d!r}")
    if len(set(domains)) != len(domains):
        raise ValueError("operator_domains must be unique")


class ApplicationPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    # The public, opaque id an application puts in login URLs (0.14.0).
    client_id: str | None = None
    name: str = Field(min_length=1)
    enabled: bool
    created_at: datetime
    redirect_uri: str | None = Field(
        default=None,
        description="Thin callback URL for AUTHENTICATED (ADR-0024). Not OIDC.",
    )


class CreateApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    redirect_uri: str | None = Field(default=None, min_length=1, max_length=512)


class PatchApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=256)
    enabled: bool | None = None
    redirect_uri: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def _at_least_one(self) -> PatchApplicationRequest:
        if self.name is None and self.enabled is None and self.redirect_uri is None:
            raise ValueError("at least one field is required")
        return self


class GroupRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class AdminUserPublic(BaseModel):
    """Directory row. Password hash is never included."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    email: str = Field(min_length=1)
    enabled: bool
    is_admin: bool
    created_at: datetime
    # What an operator looks at first (U-2): who the user is grouped with,
    # whether a step-up can succeed (ADR-0037), and whether the account is used.
    groups: list[GroupRef] = Field(default_factory=list)
    passkeys: int = Field(default=0, ge=0)
    last_login_at: datetime | None = None


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1)
    password: str = Field(min_length=1)
    is_admin: bool = False


class PatchUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    is_admin: bool | None = None
    password: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _at_least_one(self) -> PatchUserRequest:
        if self.enabled is None and self.is_admin is None and self.password is None:
            raise ValueError("at least one field is required")
        return self


class GroupMemberPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1)
    email: str = Field(min_length=1)


class PermissionPublic(BaseModel):
    """One thing that can be done, on one application.

    ``scope`` is the wire form a client checks against — ``"transfer:create"``.
    It is derived, never stored twice.
    """

    model_config = ConfigDict(extra="forbid")

    permission_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    resource: str = Field(min_length=1, max_length=64)
    operation: str = Field(min_length=1, max_length=64)
    description: str = ""
    # Always derived from resource/operation, never trusted from input — but
    # declared as a field rather than computed so a client can GET this object
    # and PUT it back unchanged.
    scope: str = ""

    @model_validator(mode="after")
    def _derive_scope(self) -> PermissionPublic:
        object.__setattr__(self, "scope", f"{self.resource}:{self.operation}")
        return self


class RolePublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    role_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    permission_count: int = Field(ge=0)
    created_at: datetime


class RoleDetail(RolePublic):
    permissions: list[PermissionPublic] = Field(default_factory=list)


class CreateRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_id: str | None = Field(default=None, min_length=1, max_length=128)
    application_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)


class PatchRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def _at_least_one(self) -> PatchRoleRequest:
        if self.name is None and self.description is None:
            raise ValueError("at least one field is required")
        return self


class SetRolePermissionsRequest(BaseModel):
    """Replace a role's permission set wholesale. Empty list is legal (a role
    that grants sign-in and nothing else)."""

    model_config = ConfigDict(extra="forbid")

    permission_ids: list[str] = Field(default_factory=list)


class CreatePermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=64)
    operation: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=512)


class GroupRolePublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    name: str = Field(min_length=1)


class GroupPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    group_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    member_count: int = Field(ge=0)
    created_at: datetime


class GroupDetail(GroupPublic):
    members: list[GroupMemberPublic] = Field(default_factory=list)
    roles: list[GroupRolePublic] = Field(default_factory=list)


class CreateGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str | None = Field(default=None, min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=512)


class PatchGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def _at_least_one(self) -> PatchGroupRequest:
        if self.name is None and self.description is None:
            raise ValueError("at least one field is required")
        return self


class AddGroupMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1)


class AddGroupRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_id: str = Field(min_length=1, max_length=128)


class DecisionRecord(BaseModel):
    """One scored login, including per-signal reasons (thesis differentiator)."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    occurred_at: datetime
    tenant_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    # The engine's verdict, and what was actually applied (ADR-0034). They
    # differ while the tenant's engine is in MONITOR.
    action: Action
    enforced_action: Action
    engine_mode: EngineMode
    # Country/ASN came from the presenter override (ADR-0032).
    simulated: bool = False
    reasons: list[Reason] = Field(default_factory=list)
    model_version: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    fallback: bool = False
    # What the login looked like and what the model compared it with: where
    # from, which network and device, and which of those were familiar.
    # Optional: records written before 0.13.0 lack them.
    login: LoginEventSnapshot | None = None
    features: FeatureVectorV1 | None = None
    # When the user passed the step-up this decision asked for (RF-11 / RF-18).
    # None: no step-up, or not passed (abandoned, or an attacker without it).
    step_up_passed_at: datetime | None = None


class DecisionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DecisionRecord]
    count: int = Field(ge=0)


class HourCount(BaseModel):
    """Decisions in one UTC hour, by enforced action. The console folds hours
    into its own local days."""

    model_config = ConfigDict(extra="forbid")

    hour: datetime
    counts: dict[str, int]


class CountryCount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    country: str
    count: int = Field(ge=0)


class DecisionSummary(BaseModel):
    """A tenant's decisions since ``since``, counted in the store (the console's
    Resumen). Replaces counting the newest 200 records in the browser, which a
    single load test filled."""

    model_config = ConfigDict(extra="forbid")

    since: datetime
    total: int = Field(ge=0)
    by_action: dict[str, int]
    # MONITOR: the engine would have allowed, the base policy asked for a step-up.
    saved_prompts: int = Field(ge=0)
    hours: list[HourCount]
    countries: list[CountryCount]
