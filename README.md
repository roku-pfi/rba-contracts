# rba-contracts

Versioned **API / event / feature / model / policy** contracts for the RBA polyrepo
([`github.com/roku-pfi`](https://github.com/roku-pfi)). This library exists to defeat
**contract drift** between services — the counterpart of `rba-features` defeating
train/serve skew.

## What is frozen (v0.1.0 / Phase 2)

| Artifact | Path | Role |
|---|---|---|
| Feature schema | `schemas/feature-vector.schema.json` + `FeatureVectorV1` | Names, types, order (`FEATURE_NAMES`) |
| Model I/O | `schemas/model-prediction.schema.json`, `model-artifact.schema.json` | `predict_proba`-compatible score + artifact metadata |
| PDP API | `openapi/risk-evaluate.yaml` | `POST /risk/evaluate` |
| Bus event | `asyncapi/decision-events.yaml` | `rba.decision.made.v1` (outbox / `event_id`) |
| Policy config | `schemas/policy-config.schema.json` + `examples/policy-config.yaml` | score→level / level→action |

Executable Pydantic models live under `src/rba_contracts/` and are what
`rba-decision-service` (Phase 3) will import. YAML/JSON Schema files are the
language-neutral source of truth for OpenAPI/AsyncAPI tooling.

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

## Design notes (see ADR-0008 in `../docs`)

- **`risk_score` ∈ [0, 1]** — policy thresholds are on this scale. Freeman’s native
  `logrisk` is optional on `ModelPrediction`; serving maps it via
  `proba_mapping.method` (default `logistic_logrisk`).
- **Actions:** `ALLOW` · `REQUIRE_MFA` · `REAUTHENTICATE` · `BLOCK`.
- **`event_id`** is caller-supplied on `/risk/evaluate` and reused as the outbox /
  bus idempotency key.
- **`is_attack_ip` is not part of any request/feature contract** (ADR-0004).
- Feature implementation remains in `rba-features`; this repo only freezes the
  schema. `FEATURE_NAMES` here must match `rba_features.features.FEATURE_NAMES`.

## Status

Phase 2 freeze. Roadmap: `../docs/plans/status.md`.
