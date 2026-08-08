"""Validate examples + Python models stay aligned with the frozen schemas."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from rba_contracts import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    FREEMAN_FEATURES,
    Action,
    DecisionMadeEvent,
    FeatureVectorV1,
    ModelArtifactMetadata,
    PolicyConfig,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
    apply_policy,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SCHEMAS = ROOT / "schemas"


def _load_json(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text())


def _schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text())


def test_feature_names_order_and_version() -> None:
    assert FEATURE_SCHEMA_VERSION == "1.0.0"
    assert FEATURE_NAMES == (
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
    assert FREEMAN_FEATURES == (
        "ip_address",
        "asn",
        "country",
        "device_type",
        "os",
        "browser",
        "hour",
    )


def test_feature_vector_example_matches_schema_and_model() -> None:
    raw = _load_json("feature-vector.json")
    Draft202012Validator(_schema("feature-vector.schema.json")).validate(raw)
    vec = FeatureVectorV1.model_validate(raw)
    assert vec.as_ordered_list() == [raw[n] for n in FEATURE_NAMES]


def test_model_artifact_example() -> None:
    raw = _load_json("model-artifact.json")
    Draft202012Validator(_schema("model-artifact.schema.json")).validate(raw)
    meta = ModelArtifactMetadata.model_validate(raw)
    assert meta.proba_mapping is not None
    assert meta.proba_mapping.method == "logistic_logrisk"


def test_evaluate_request_response_roundtrip() -> None:
    req = RiskEvaluateRequest.model_validate(_load_json("evaluate-request.json"))
    assert req.to_feature_event()["ip_address"] == "203.0.113.10"
    # Leakage-sensitive field must not be part of the request model.
    assert "is_attack_ip" not in RiskEvaluateRequest.model_fields

    resp = RiskEvaluateResponse.model_validate(_load_json("evaluate-response.json"))
    assert resp.action == Action.REQUIRE_MFA
    assert resp.risk_level == RiskLevel.MEDIUM
    assert 0.0 <= resp.risk_score <= 1.0


def test_decision_made_event_example() -> None:
    event = DecisionMadeEvent.model_validate(_load_json("decision-made-event.json"))
    assert event.features is not None
    assert event.features.device_type_seen_before == 0


def test_policy_config_example_and_apply() -> None:
    raw = yaml.safe_load((EXAMPLES / "policy-config.yaml").read_text())
    Draft202012Validator(_schema("policy-config.schema.json")).validate(raw)
    cfg = PolicyConfig.model_validate(raw)

    level, action = apply_policy(0.10, cfg, "unknown-app")
    assert level == RiskLevel.LOW and action == Action.ALLOW

    level, action = apply_policy(0.61, cfg, "unknown-app")
    assert level == RiskLevel.HIGH and action == Action.REAUTHENTICATE

    # High-sensitivity demo app has tighter bands: 0.61 → HIGH; 0.75 → CRITICAL.
    level, action = apply_policy(0.61, cfg, "demo-banking-app")
    assert level == RiskLevel.HIGH and action == Action.REAUTHENTICATE
    level, action = apply_policy(0.75, cfg, "demo-banking-app")
    assert level == RiskLevel.CRITICAL and action == Action.BLOCK

    level, action = apply_policy(0.0, cfg, "demo-banking-app", fallback=True)
    assert action == Action.REQUIRE_MFA
    assert level == RiskLevel.MEDIUM  # lowest level mapped to REQUIRE_MFA in defaults merge


def test_policy_rejects_unsorted_bands() -> None:
    with pytest.raises(Exception):
        PolicyConfig.model_validate(
            {
                "policy_version": "x",
                "defaults": {
                    "score_to_level": [
                        {"max": 0.8, "level": "HIGH"},
                        {"max": 0.3, "level": "LOW"},
                        {"max": 1.0, "level": "CRITICAL"},
                    ],
                    "level_to_action": {
                        "LOW": "ALLOW",
                        "MEDIUM": "REQUIRE_MFA",
                        "HIGH": "REAUTHENTICATE",
                        "CRITICAL": "BLOCK",
                    },
                    "fallback_action": "REQUIRE_MFA",
                },
            }
        )


def test_feature_names_match_rba_features_when_installed() -> None:
    """Parity guard: contracts FEATURE_NAMES == implementation FEATURE_NAMES."""
    pytest.importorskip("rba_features")
    from rba_features.features import FEATURE_NAMES as impl_names

    assert tuple(impl_names) == FEATURE_NAMES
