"""FeatureVectorV1 — frozen mirror of rba_features.features.FEATURE_NAMES.

The implementation lives in rba-features; this schema is the cross-repo contract
(names, types, order, version). Changing either side without the other is a
breaking change — bump FEATURE_SCHEMA_VERSION.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

FEATURE_SCHEMA_VERSION = "1.0.0"

# Must stay identical (order included) to rba_features.features.FEATURE_NAMES.
FEATURE_NAMES: tuple[str, ...] = (
    "user_login_count",
    "ip_seen_before",
    "asn_seen_before",
    "country_seen_before",
    "device_type_seen_before",
    "os_seen_before",
    "browser_seen_before",
    "hour_seen_before",
    "seconds_since_last_login",
    "failed_logins_last_24h",
)


class FeatureVectorV1(BaseModel):
    """Ordered feature vector for supervised models / audit snapshots."""

    model_config = ConfigDict(extra="forbid")

    user_login_count: int = Field(ge=0)
    ip_seen_before: int = Field(ge=0, le=1)
    asn_seen_before: int = Field(ge=0, le=1)
    country_seen_before: int = Field(ge=0, le=1)
    device_type_seen_before: int = Field(ge=0, le=1)
    os_seen_before: int = Field(ge=0, le=1)
    browser_seen_before: int = Field(ge=0, le=1)
    hour_seen_before: int = Field(ge=0, le=1)
    seconds_since_last_login: float
    failed_logins_last_24h: int = Field(ge=0)

    def as_ordered_list(self) -> list[Any]:
        """Values in FEATURE_NAMES order (for sklearn / LightGBM matrices)."""
        data = self.model_dump()
        return [data[name] for name in FEATURE_NAMES]
