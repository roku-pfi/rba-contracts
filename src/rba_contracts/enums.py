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
