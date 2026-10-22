"""Shared enums for the PDP / policy / event contracts."""

from __future__ import annotations

from enum import Enum


class Action(str, Enum):
    """Enforcement action returned to the PEP."""

    ALLOW = "ALLOW"
    REQUIRE_MFA = "REQUIRE_MFA"
    REAUTHENTICATE = "REAUTHENTICATE"
    BLOCK = "BLOCK"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BasePolicy(str, Enum):
    """What a tenant enforces on a correct password without the engine (ADR-0034).

    The second factor, whenever one is required, is always the passkey.
    """

    PASSWORD_ONLY = "PASSWORD_ONLY"
    ALWAYS_MFA = "ALWAYS_MFA"


class EngineMode(str, Enum):
    """How a tenant uses the engine's verdict (ADR-0034).

    ``OFF``: the PDP is not consulted; the base policy applies.
    ``MONITOR``: the PDP scores and records; the base policy applies.
    ``ACTIVE``: the PDP's verdict applies.
    """

    OFF = "OFF"
    MONITOR = "MONITOR"
    ACTIVE = "ACTIVE"
