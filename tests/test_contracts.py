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
    AdminUserPublic,
    ApplicationPublic,
    CallbackTokenRequest,
    CallbackTokenResponse,
    CreateGroupRequest,
    CreateUserRequest,
    GroupDetail,
    RoleDetail,
    DecisionMadeEvent,
    DecisionRecord,
    FeatureVectorV1,
    LoginConfirmedEvent,
    LoginConfirmRequest,
    LoginOutcome,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    MfaWebAuthnOptionsRequest,
    MfaWebAuthnOptionsResponse,
    MfaWebAuthnVerifyRequest,
    ModelArtifactMetadata,
    PatchGroupRequest,
    PatchUserRequest,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
    SessionResponse,
    TenantPolicy,
    TenantPublic,
    BasePolicy,
    CreateTenantRequest,
    EngineMode,
    apply_policy,
    enforced_action,
    outcome_from_action,
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


def test_login_confirmed_event_example() -> None:
    event = LoginConfirmedEvent.model_validate(_load_json("login-confirmed-event.json"))
    assert event.event_id != event.decision_event_id
    assert event.login.login_successful is True
    LoginConfirmRequest(event_id=event.decision_event_id, tenant_id=event.tenant_id)


def _tenant_policy(name: str) -> dict:
    return yaml.safe_load((EXAMPLES / f"tenant-policy-{name}.yaml").read_text())


@pytest.mark.parametrize("name", ["roku-bank", "kaze-labs", "rokusec"])
def test_tenant_policy_examples_match_schema(name: str) -> None:
    raw = _tenant_policy(name)
    Draft202012Validator(_schema("tenant-policy.schema.json")).validate(raw)
    assert TenantPolicy.model_validate(raw).tenant_id == name


def test_apply_policy_bands_and_fallback() -> None:
    bank = TenantPolicy.model_validate(_tenant_policy("roku-bank"))
    assert apply_policy(0.35, bank) == (RiskLevel.LOW, Action.ALLOW)
    assert apply_policy(0.55, bank) == (RiskLevel.MEDIUM, Action.REQUIRE_MFA)
    assert apply_policy(0.75, bank) == (RiskLevel.HIGH, Action.REAUTHENTICATE)
    # D-2: a score never blocks; the top band steps up too (blocks come from rules).
    assert apply_policy(0.95, bank) == (RiskLevel.CRITICAL, Action.REAUTHENTICATE)
    # Scorer failure: the fallback action at the lowest level that maps to it.
    assert apply_policy(0.0, bank, fallback=True) == (RiskLevel.MEDIUM, Action.REQUIRE_MFA)


def test_enforced_action_follows_engine_mode() -> None:
    """ADR-0034: MONITOR keeps the tenant's existing control; ACTIVE applies the verdict."""
    bank = TenantPolicy.model_validate(_tenant_policy("roku-bank"))
    assert (bank.base_policy, bank.engine_mode) == (BasePolicy.ALWAYS_MFA, EngineMode.MONITOR)
    # Monitoring: the engine would allow, but the bank still asks for the passkey…
    assert enforced_action(Action.ALLOW, bank) == Action.REQUIRE_MFA
    # …and a verdict the engine would block is not enforced either.
    assert enforced_action(Action.BLOCK, bank) == Action.REQUIRE_MFA

    active = bank.model_copy(update={"engine_mode": EngineMode.ACTIVE})
    assert enforced_action(Action.ALLOW, active) == Action.ALLOW
    assert enforced_action(Action.BLOCK, active) == Action.BLOCK

    off = bank.model_copy(update={"engine_mode": EngineMode.OFF, "base_policy": BasePolicy.PASSWORD_ONLY})
    assert enforced_action(Action.BLOCK, off) == Action.ALLOW


def test_platform_tenant_always_asks_for_a_passkey() -> None:
    """The ladder alone gives 'always MFA plus escalation' under ACTIVE."""
    platform = TenantPolicy.model_validate(_tenant_policy("rokusec"))
    _, verdict = apply_policy(0.0, platform)
    assert enforced_action(verdict, platform) == Action.REQUIRE_MFA
    _, verdict = apply_policy(0.99, platform)
    assert enforced_action(verdict, platform) == Action.REAUTHENTICATE


def test_policy_rejects_unsorted_bands() -> None:
    raw = _tenant_policy("kaze-labs")
    raw["score_to_level"] = [
        {"max": 0.8, "level": "HIGH"},
        {"max": 0.3, "level": "LOW"},
        {"max": 1.0, "level": "CRITICAL"},
    ]
    with pytest.raises(Exception):
        TenantPolicy.model_validate(raw)


def test_tenant_examples_and_domain_rules() -> None:
    tenant = TenantPublic.model_validate(_load_json("admin-tenant.json"))
    assert tenant.operator_domains == ["rokubank.example"]
    assert tenant.branding.login_style == "tenant"
    assert tenant.is_platform is False

    CreateTenantRequest.model_validate(
        {"tenant_id": "kaze-labs", "name": "Kaze Labs", "operator_domains": ["kazelabs.example"]}
    )
    for bad in (["KazeLabs.example"], ["kazelabs"], ["a.example", "a.example"]):
        with pytest.raises(Exception):
            CreateTenantRequest.model_validate(
                {"tenant_id": "kaze-labs", "name": "Kaze Labs", "operator_domains": bad}
            )
    with pytest.raises(Exception):
        CreateTenantRequest.model_validate({"tenant_id": "Kaze Labs", "name": "x"})


def test_evaluate_and_event_carry_tenant_and_enforcement() -> None:
    req = RiskEvaluateRequest.model_validate(_load_json("evaluate-request.json"))
    assert req.tenant_id == "roku-bank" and req.simulated is False
    with pytest.raises(Exception):
        RiskEvaluateRequest.model_validate(
            {k: v for k, v in _load_json("evaluate-request.json").items() if k != "tenant_id"}
        )
    resp = RiskEvaluateResponse.model_validate(_load_json("evaluate-response.json"))
    assert (resp.enforced_action, resp.engine_mode) == (Action.REQUIRE_MFA, EngineMode.MONITOR)
    assert "monitored_action" not in RiskEvaluateResponse.model_fields

    event = DecisionMadeEvent.model_validate(_load_json("decision-made-event.json"))
    assert event.tenant_id == "roku-bank"
    record = DecisionRecord.model_validate(_load_json("admin-decision.json"))
    assert record.tenant_id == event.tenant_id


def test_feature_names_match_rba_features_when_installed() -> None:
    """Parity guard: contracts FEATURE_NAMES == implementation FEATURE_NAMES."""
    pytest.importorskip("rba_features")
    from rba_features.features import FEATURE_NAMES as impl_names

    assert tuple(impl_names) == FEATURE_NAMES


def test_idp_login_examples_roundtrip() -> None:
    req = LoginRequest.model_validate(_load_json("idp-login-request.json"))
    assert req.email == "demo@example.com"
    assert "password" in LoginRequest.model_fields
    assert "password" not in LoginResponse.model_fields

    resp = LoginResponse.model_validate(_load_json("idp-login-response.json"))
    assert resp.outcome == LoginOutcome.MFA_REQUIRED
    assert resp.action == Action.REQUIRE_MFA
    assert resp.session is None
    assert resp.challenge_id is not None

    mfa = MfaVerifyRequest.model_validate(_load_json("idp-mfa-verify-request.json"))
    assert mfa.code == "000000"

    opts_req = MfaWebAuthnOptionsRequest.model_validate(
        _load_json("idp-mfa-webauthn-options-request.json")
    )
    assert opts_req.challenge_id == mfa.challenge_id
    opts = MfaWebAuthnOptionsResponse.model_validate(
        _load_json("idp-mfa-webauthn-options-response.json")
    )
    assert opts.mode.value == "create"
    assert opts.public_key["rp"]["id"] == "localhost"
    assertion = MfaWebAuthnVerifyRequest.model_validate(
        _load_json("idp-mfa-webauthn-verify-request.json")
    )
    assert assertion.credential["type"] == "public-key"

    session = SessionResponse.model_validate(_load_json("idp-session-response.json"))
    assert session.user.email == "demo@example.com"
    assert session.user.is_admin is False
    assert session.user.tenant_id == "roku-bank"

    token_req = CallbackTokenRequest.model_validate(
        _load_json("idp-callback-token-request.json")
    )
    assert token_req.code
    token_resp = CallbackTokenResponse.model_validate(
        _load_json("idp-callback-token-response.json")
    )
    assert token_resp.user.email == "demo@example.com"
    assert token_resp.session.token


def test_admin_examples_roundtrip() -> None:
    user = AdminUserPublic.model_validate(_load_json("admin-user.json"))
    assert user.is_admin is True
    assert "password" not in AdminUserPublic.model_fields

    app = ApplicationPublic.model_validate(_load_json("admin-application.json"))
    assert app.application_id == "roku-bank-web"
    assert app.tenant_id == "roku-bank"
    assert app.redirect_uri == "http://localhost:8002/callback"

    created = CreateUserRequest.model_validate(_load_json("admin-create-user.json"))
    assert created.is_admin is False

    decision = DecisionRecord.model_validate(_load_json("admin-decision.json"))
    assert decision.action == Action.REQUIRE_MFA
    assert decision.reasons[0].signal == "device_type"

    group = GroupDetail.model_validate(_load_json("admin-group.json"))
    assert group.group_id == "grp_banking"
    assert group.members[0].email == "demo@example.com"
    # ADR-0029: a group holds roles, not an `access` grant.
    assert group.roles[0].role_id == "role_bank_customer"
    assert group.roles[0].application_id == "roku-bank-web"

    role = RoleDetail.model_validate(_load_json("admin-role.json"))
    assert role.permission_count == 3
    # `scope` is derived, so it round-trips without being stored twice.
    assert [p.scope for p in role.permissions] == [
        "account:read",
        "transaction:read",
        "transfer:create",
    ]

    created_group = CreateGroupRequest.model_validate(_load_json("admin-create-group.json"))
    assert created_group.name == "Banking users"

    with pytest.raises(Exception):
        PatchUserRequest.model_validate({})
    with pytest.raises(Exception):
        PatchGroupRequest.model_validate({})


def test_outcome_from_action() -> None:
    assert outcome_from_action(Action.ALLOW) == LoginOutcome.AUTHENTICATED
    assert outcome_from_action(Action.REQUIRE_MFA) == LoginOutcome.MFA_REQUIRED
    assert outcome_from_action(Action.REAUTHENTICATE) == LoginOutcome.REAUTH_REQUIRED
    assert outcome_from_action(Action.BLOCK) == LoginOutcome.BLOCKED


def test_idp_login_response_allows_identity_only_stub() -> None:
    """IdP-2 may answer without PDP fields."""
    resp = LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
    assert resp.user_id is None
    assert resp.action is None
    dumped = resp.model_dump()
    assert "password" not in dumped


def test_access_denied_is_an_idp_outcome_not_a_pdp_action() -> None:
    resp = LoginResponse(
        outcome=LoginOutcome.ACCESS_DENIED,
        user_id="usr_demo",
        detail="user is not granted access to this application",
    )
    assert resp.action is None
    assert LoginOutcome.ACCESS_DENIED.value == "ACCESS_DENIED"


def test_a_login_names_its_application_exactly_once() -> None:
    import pytest
    from pydantic import ValidationError

    from rba_contracts import LoginRequest

    base = {"email": "a@b.example", "password": "x", "ip_address": "203.0.113.1"}
    assert LoginRequest(**base, client_id="rk_abc").client_id == "rk_abc"
    assert LoginRequest(**base, application_id="roku-bank-web").application_id == "roku-bank-web"
    for bad in ({}, {"client_id": "rk_abc", "application_id": "roku-bank-web"}):
        with pytest.raises(ValidationError):
            LoginRequest(**base, **bad)
