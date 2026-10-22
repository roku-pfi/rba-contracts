"""Per-tenant policy: score→level, level→action, base policy, engine mode.

One ``TenantPolicy`` per tenant (ADR-0033); the PDP stores them in Postgres and
every replica reads the same rows. Two pure helpers turn a score into the
engine's *verdict* (``apply_policy``) and a verdict into what the PEP must
*enforce* (``enforced_action``, ADR-0034).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rba_contracts.enums import Action, BasePolicy, EngineMode, RiskLevel


class ScoreBand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max: float = Field(ge=0.0, le=1.0)
    level: RiskLevel


class LevelToAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    LOW: Action
    MEDIUM: Action
    HIGH: Action
    CRITICAL: Action

    def for_level(self, level: RiskLevel) -> Action:
        return getattr(self, level.value)


class TenantPolicy(BaseModel):
    """Everything that decides a login for one tenant. Editable without redeploy (RNF-05)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1)
    # ADR-0034: what the tenant does without the engine, and whether the
    # engine's verdict is enforced, only recorded, or not computed at all.
    base_policy: BasePolicy = BasePolicy.PASSWORD_ONLY
    engine_mode: EngineMode = EngineMode.ACTIVE
    score_to_level: list[ScoreBand] = Field(min_length=1)
    level_to_action: LevelToAction
    # When the scorer or the profile store fails inside the PDP.
    fallback_action: Action

    @model_validator(mode="after")
    def _bands_sorted_and_cover(self) -> TenantPolicy:
        maxima = [b.max for b in self.score_to_level]
        if maxima != sorted(maxima):
            raise ValueError("score_to_level bands must be sorted by ascending max")
        if maxima[-1] != 1.0:
            raise ValueError("score_to_level must cover up to max=1.0")
        return self


def score_to_level(score: float, bands: list[ScoreBand]) -> RiskLevel:
    if not 0.0 <= score <= 1.0:
        raise ValueError("risk_score must be in [0, 1]")
    for band in bands:
        if score <= band.max:
            return band.level
    return bands[-1].level


def apply_policy(
    risk_score: float,
    policy: TenantPolicy,
    *,
    fallback: bool = False,
) -> tuple[RiskLevel, Action]:
    """Map risk_score → (level, verdict) under a tenant's policy.

    When fallback=True (scorer/profile failure), returns
    ``policy.fallback_action`` and the *lowest* RiskLevel whose configured
    action equals that fallback (so the PEP still gets a decisive action).
    Callers should set ``RiskEvaluateResponse.fallback=true`` and treat
    ``risk_score`` as non-informative in that case.
    """
    if fallback:
        for level in RiskLevel:
            if policy.level_to_action.for_level(level) == policy.fallback_action:
                return level, policy.fallback_action
        return RiskLevel.HIGH, policy.fallback_action
    level = score_to_level(risk_score, policy.score_to_level)
    return level, policy.level_to_action.for_level(level)


def base_action(base: BasePolicy) -> Action:
    """The action a base policy enforces on a correct password."""
    return Action.REQUIRE_MFA if base is BasePolicy.ALWAYS_MFA else Action.ALLOW


def enforced_action(verdict: Action, policy: TenantPolicy) -> Action:
    """What the PEP must apply (ADR-0034).

    ``ACTIVE`` enforces the engine's verdict, escalation floors included.
    ``MONITOR`` and ``OFF`` enforce the base policy; under ``MONITOR`` the
    verdict is still recorded, so the operator can see what would have happened.
    """
    if policy.engine_mode is EngineMode.ACTIVE:
        return verdict
    return base_action(policy.base_policy)
