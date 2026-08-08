"""Score→level / level→action policy config + pure apply helper."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rba_contracts.enums import Action, RiskLevel


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


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score_to_level: list[ScoreBand] = Field(min_length=1)
    level_to_action: LevelToAction
    fallback_action: Action

    @model_validator(mode="after")
    def _bands_sorted_and_cover(self) -> PolicyBundle:
        maxima = [b.max for b in self.score_to_level]
        if maxima != sorted(maxima):
            raise ValueError("score_to_level bands must be sorted by ascending max")
        if maxima[-1] != 1.0:
            raise ValueError("score_to_level must cover up to max=1.0")
        return self


class ApplicationOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensitivity: Literal["low", "standard", "high", "critical"] | None = None
    score_to_level: list[ScoreBand] | None = None
    level_to_action: LevelToAction | None = None
    fallback_action: Action | None = None


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: str = Field(min_length=1)
    defaults: PolicyBundle
    applications: dict[str, ApplicationOverride] = Field(default_factory=dict)

    def bundle_for(self, application_id: str) -> PolicyBundle:
        """Merge defaults with optional per-app overrides."""
        override = self.applications.get(application_id)
        if override is None:
            return self.defaults
        return PolicyBundle(
            score_to_level=override.score_to_level or self.defaults.score_to_level,
            level_to_action=override.level_to_action or self.defaults.level_to_action,
            fallback_action=override.fallback_action or self.defaults.fallback_action,
        )


def score_to_level(score: float, bands: list[ScoreBand]) -> RiskLevel:
    if not 0.0 <= score <= 1.0:
        raise ValueError("risk_score must be in [0, 1]")
    for band in bands:
        if score <= band.max:
            return band.level
    return bands[-1].level


def apply_policy(
    risk_score: float,
    config: PolicyConfig,
    application_id: str,
    *,
    fallback: bool = False,
) -> tuple[RiskLevel, Action]:
    """Map risk_score → (level, action) for an application.

    When fallback=True (scorer/profile failure), returns
    ``bundle.fallback_action`` and the *lowest* RiskLevel whose configured
    action equals that fallback (so the PEP still gets a decisive action).
    Callers should set ``RiskEvaluateResponse.fallback=true`` and treat
    ``risk_score`` as non-informative in that case.
    """
    bundle = config.bundle_for(application_id)
    if fallback:
        for level in RiskLevel:
            if bundle.level_to_action.for_level(level) == bundle.fallback_action:
                return level, bundle.fallback_action
        return RiskLevel.HIGH, bundle.fallback_action
    level = score_to_level(risk_score, bundle.score_to_level)
    return level, bundle.level_to_action.for_level(level)
