"""IdP-6/7 admin console contracts (users, applications, groups, decisions).

Policy GET/PUT reuses ``PolicyConfig``. Identity CRUD is served by ``rba-idp``;
the decision list is the audit-service read model. Groups (IdP-7) grant
app-scoped ``access``; they do not replace ``is_admin``.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rba_contracts.enums import Action, RiskLevel
from rba_contracts.evaluate import Reason


class AppPermission(str, Enum):
    """What a group may do on a registered application. Thesis-scale: access only."""

    ACCESS = "access"


class ApplicationPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1)
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


class AdminUserPublic(BaseModel):
    """Directory row. Password hash is never included."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1)
    email: str = Field(min_length=1)
    enabled: bool
    is_admin: bool
    created_at: datetime


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


class GroupGrantPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1)
    permission: AppPermission = AppPermission.ACCESS


class GroupPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""
    member_count: int = Field(ge=0)
    created_at: datetime


class GroupDetail(GroupPublic):
    members: list[GroupMemberPublic] = Field(default_factory=list)
    grants: list[GroupGrantPublic] = Field(default_factory=list)


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


class CreateGroupGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application_id: str = Field(min_length=1, max_length=128)
    permission: AppPermission = AppPermission.ACCESS


class DecisionRecord(BaseModel):
    """One scored login, including per-signal reasons (thesis differentiator)."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    occurred_at: datetime
    application_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    action: Action
    reasons: list[Reason] = Field(default_factory=list)
    model_version: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    fallback: bool = False


class DecisionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DecisionRecord]
    count: int = Field(ge=0)
