# Rebrand Architecture V1

## Product Naming
- External product label: **Cerberus Pro**
- Internal canonical backend module: **Ares Core** (`backend/ares_api.py`)
- Compatibility facade: `backend/cerberus_pro_api_secure.py`

## Single-Orchestrator Model
- One authoritative orchestrator flow:
  - preflight
  - discovery
  - execution
  - correlation
  - verdict
- One verdict authority: backend only.
- Frontend renders state; it does not upgrade verdict certainty.

## Layering
- `backend/core/`: domain logic, coverage, verdict, orchestration.
- `backend/engines/`: execution adapters with unified outputs.
- `backend/db/`: persistence and migrations.
- `backend/routers/`: API route surface only.
- `backend/archive/`: non-runtime legacy scripts.

## Contract Stability
- Coverage schema versioned (`coverage.v1`) and persisted.
- Conclusive blockers shape normalized and stable end-to-end.
- Jobs API remains the integration anchor for UI.

## Deprecation Rules
1. No duplicated runtime API modules.
2. No patch scripts in backend root.
3. No route collisions with conflicting request models.
4. New modules require:
   - ownership
   - tests
   - contract documentation.
