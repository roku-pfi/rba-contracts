# rba-contracts

Versioned **API / event / feature / model / policy** contracts for the RBA
polyrepo. This library exists to defeat **contract drift** between services —
the counterpart of `rba-features` defeating train/serve skew.

Package version: **0.4.0** (IdP-7 groups + `ACCESS_DENIED`).
PDP / feature / policy freeze was **v0.1.0**
([ADR-0008](../docs/decisions/0008-contracts-freeze.md));
`LoginEventSnapshot` landed in **v0.1.1**; IdP login API in **v0.2.0**;
admin console in **v0.3.0**.

YAML/JSON Schema files are the language-neutral source of truth. Executable
Pydantic models under `src/rba_contracts/` are what Python services import.

> Status: [`../docs/plans/status.md`](../docs/plans/status.md). AI: [`AGENTS.md`](AGENTS.md).

## What is frozen

| Artifact | Path | Role |
|---|---|---|
| Feature schema | `schemas/feature-vector.schema.json` + `FeatureVectorV1` | Names, types, order (`FEATURE_NAMES`) |
| Model I/O | `schemas/model-prediction.schema.json`, `model-artifact.schema.json` | `predict_proba`-compatible score + artifact metadata |
| PDP API | `openapi/risk-evaluate.yaml` | `POST /risk/evaluate`, `GET`/`PUT /policy` |
| IdP API | `openapi/idp.yaml` | `POST /login`, `/mfa/verify`, `GET /session`, `POST /logout` |
| IdP admin | `openapi/idp-admin.yaml` | `/admin/api` users, apps, groups, decisions, policy |
| Audit read | `openapi/audit.yaml` | `GET /decisions` (IdP-6 decision browser) |
| Bus event | `asyncapi/decision-events.yaml` | `rba.decision.made.v1` (outbox / `event_id`) |
| Policy config | `schemas/policy-config.schema.json` + `examples/policy-config.yaml` | score→level / level→action |

Canonical JSON examples live in `examples/` and are validated by
`tests/test_contracts.py` against both JSON Schema and the Pydantic models.

## Layout

```
openapi/
├── risk-evaluate.yaml     # PDP (+ GET/PUT /policy)
├── idp.yaml               # PEP login
├── idp-admin.yaml         # IdP-6/7 admin BFF (groups in 0.4.0)
└── audit.yaml             # audit-service decision read API
asyncapi/
└── decision-events.yaml
schemas/                   # JSON Schema
examples/                  # request/response/event/policy samples
src/rba_contracts/
├── enums.py               # Action, RiskLevel
├── features.py            # FEATURE_NAMES, FeatureVectorV1
├── model.py               # ModelPrediction, ModelArtifactMetadata, FREEMAN_FEATURES
├── evaluate.py            # RiskEvaluateRequest / Response, Reason
├── policy.py              # PolicyConfig, apply_policy()
├── events.py              # DecisionMadeEvent, LoginEventSnapshot
├── idp.py                 # LoginRequest/Response, session, MFA, outcome_from_action
└── admin.py               # users, apps, groups, DecisionRecord
tests/test_contracts.py
```

## PDP: `POST /risk/evaluate`

Caller (PEP) authenticates first, then posts login **signals** (never a
password). `event_id` is caller-supplied and reused as the outbox / bus
idempotency key.

Request fields (canonical names matching `rba-features`): `event_id`,
`application_id`, `user_id`, `timestamp`, `ip_address`, optional `asn`,
`country`, `device_type`, `os`, `browser`, `user_agent`, `device_id`,
`login_successful` (default true).

**Not on the contract:** `is_attack_ip` (leakage), RTT, geo distance.

Response: `risk_score` ∈ [0, 1], `risk_level`, `action`, `reasons[]`,
`model_version`, `policy_version`, `feature_schema_version`, `fallback`,
`scored_at`.

### Actions and levels

| `Action` | Typical meaning |
|---|---|
| `ALLOW` | Proceed |
| `REQUIRE_MFA` | Step-up factor |
| `REAUTHENTICATE` | Fresh credentials |
| `BLOCK` | Reject |

`RiskLevel`: `LOW` · `MEDIUM` · `HIGH` · `CRITICAL`.

Policy maps score→level (sorted bands covering up to `max=1.0`) then
level→action. Per-application overrides are allowed. Scorer/profile failure
uses `fallback_action` and sets `fallback=true` (`risk_score` is then
non-informative). Helper: `apply_policy(score, config, application_id)`.

Default example bands (`examples/policy-config.yaml`): ≤0.30 LOW, ≤0.60
MEDIUM, ≤0.80 HIGH, else CRITICAL. `demo-banking-app` is tighter;
`demo-forum-app` is looser.

### Freeman vs policy scale

Freeman’s native output is `logrisk`. Serving maps it to `risk_score` via
`proba_mapping.method` (default `logistic_logrisk`). Policy thresholds are
always on [0, 1]. Optional per-signal `SignalContribution` list becomes
structured `Reason`s on the PDP response.

`FREEMAN_FEATURES` must match `rba-features` / `ml.models.freeman`:
`ip_address`, `asn`, `country`, `device_type`, `os`, `browser`, `hour`.

`FEATURE_NAMES` here **must** match `rba_features.features.FEATURE_NAMES`
(order included). Changing either side without the other is a breaking
change — bump `FEATURE_SCHEMA_VERSION`.

## IdP: login / MFA / session (v0.2.0 + ACCESS_DENIED in 0.4.0)

Thesis-scale shell, not OIDC/SAML ([ADR-0014](../docs/decisions/0014-thesis-scale-idp-platform.md)).
Implemented by `rba-idp`.

| Outcome | From |
|---|---|
| `AUTHENTICATED` | PDP `ALLOW` |
| `MFA_REQUIRED` | PDP `REQUIRE_MFA` |
| `REAUTH_REQUIRED` | PDP `REAUTHENTICATE` |
| `BLOCKED` | PDP `BLOCK` |
| `INVALID_CREDENTIALS` | IdP-only (no PDP call) |
| `ACCESS_DENIED` | IdP-only: password ok, no group grant for this app (IdP-7) |

`outcome_from_action()` maps PDP actions only — services must not re-implement
it. `ACCESS_DENIED` is identity/authz, not a risk `BLOCK`.

Login request carries email + password + the same device/geo signals the PDP
needs. Password **never** appears on any response. Optional `session` /
`challenge_id` appear at IdP-4.

## IdP admin: groups (v0.4.0)

`GroupPublic` / `GroupDetail` plus membership and app-scoped grants
(`permission=access`). Admin auth remains `is_admin` (ADR-0017).

## Bus: `rba.decision.made.v1`

`DecisionMadeEvent` is the outbox payload. Consumers **must** be idempotent
on `event_id`. Phase 4+ publishers always set `login` (`LoginEventSnapshot`)
so profile-service can call `update_profile` without re-reading the PDP DB.

Channel constant: `DECISION_MADE_CHANNEL = "rba.decision.made.v1"`.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Optional parity check against the sibling feature library:

```bash
pip install -e "../rba-features"
pytest -k feature_names_match
```

Python ≥ 3.12. Runtime: pydantic ≥ 2.6, PyYAML. Dev: pytest, jsonschema.

Consumers pin this package: decision-service, IdP, event-publisher,
profile-service, audit-service (editable `../rba-contracts` in local venvs).

## Status

Phase 2 PDP freeze + IdP login/admin/groups (0.4.0). Roadmap:
`../docs/plans/status.md`.
