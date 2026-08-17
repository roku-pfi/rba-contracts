# AGENTS.md — rba-contracts

Shared **contracts library** for a risk-based authentication (RBA) thesis project.
Holds the versioned OpenAPI / AsyncAPI / JSON Schema / Pydantic models that every
service agrees on — the mitigation for **contract drift** across the polyrepo.
Portable orientation for any AI coding tool.

## Where we are / where things are stated

**Polyrepo** (org `github.com/roku-pfi`), siblings cloned side-by-side. Roadmap /
status / decisions live in the **`docs`** repo (`../docs`):

- **Current status → `../docs/plans/status.md`**
- Phase rationale → `../docs/plans/development_plan.md` §8 (Phase 2 = this repo)
- Decisions → `../docs/decisions/` (ADR-0008 freezes these contracts)
- Narrative → `../docs/devlog.md`

## Layout

```
openapi/risk-evaluate.yaml     # POST /risk/evaluate + GET/PUT /policy (PDP)
openapi/idp.yaml               # POST /login, /mfa/verify, /session, /logout, /callback/token
openapi/idp-admin.yaml         # IdP-6/7 /admin/api (groups in 0.4.0)
openapi/audit.yaml             # GET /decisions
asyncapi/decision-events.yaml  # rba.decision.made.v1 outbox/bus event
schemas/                       # JSON Schema: features, model, policy
examples/                      # canonical request/response/config samples
src/rba_contracts/             # Pydantic models + apply_policy() + outcome_from_action()
tests/test_contracts.py        # examples validate; FEATURE_NAMES parity guard
```

## Guardrails

- Do **not** silently rename/reorder `FEATURE_NAMES` — bump `FEATURE_SCHEMA_VERSION`
  and update `rba-features` in the same change set.
- Do **not** accept `is_attack_ip` on `/risk/evaluate` (leakage-sensitive).
- Do **not** put geo-distance / RTT fields on the v1 request (EDA-excluded).
- Policy thresholds are config, not code — edit `examples/policy-config.yaml` shape,
  not hard-coded cutoffs in services.
- Only commit when explicitly asked; Conventional Commits; never commit secrets.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
