# Recall / Rebranding Roadmap - Progress V1

Date: 2026-02-17
Owner: Core refactor stream

## Global Status
- Progress: **100% (scope: unificación runtime ofensivo/defensivo)**
- Current stage: **Unified runtime closed (hard-cleanup opcional)**
- Gate status: **PASS** (`recall_guard`, `deprecation_guard`, targeted tests, frontend build)
- Canonical domain lock: **`kind=unified`** end-to-end (runtime + API + frontend + DB migration `0003_kind_unified.sql`)
- API hard break: **sin aliases `/scan/omni/*` y sin contrato `config.omni`**

## Phase Breakdown

### Phase 0 - Freeze & Inventory
Status: **DONE**
- [x] Runtime inventory and legacy surface mapping.
- [x] Canonical runtime target defined (`backend.ares_api:app`).
- [x] Legacy candidates identified.
- [x] Integration organigram + matrix published (`backend/INTEGRATION_MATRIX_ORGANIGRAMA_V1.md`).

### Phase 1 - Canonical Backend Consolidation
Status: **DONE**
- [x] Compatibility facade in `backend/cerberus_pro_api_secure.py`.
- [x] Runtime scripts aligned to `backend.ares_api:app`.
- [x] Route collision cleanup (`/scan/module/status` for modular router).
- [x] Removed frontend fallback calls to legacy `/start` and `/stop`.
- [x] Unified worker runner: `classic` and `omni` now execute through a single multilevel pipeline entrypoint.
- [x] `EngineOrchestrator` integrado en `run_omni_surface_scan` (web/graphql) cuando `engine_scan_enabled=true`.
- [x] Gobernanza integrada en gate unificado (`policy_engine` en `_validate_unified_target_policy`).
- [x] Fase `ESCALATION` explícita en runner unificado (descubrimiento de cadenas bajo política).
- [x] Paridad no-web dentro del runner unificado (`direct_db`, `ws`, `mqtt`, `grpc`) sin fallback `ScanManager`.
- [x] Contrato único de sandbox: `offensiva/sandbox_runner.py` ahora es capa de compatibilidad sobre `core/sandbox_runner.py`.
- [x] `kind` canónico unificado en runtime (`unified`) con lectura retrocompatible de jobs legacy (`omni`/`classic`).
- [x] Retirada de `scan_router` legacy del runtime canónico (`ares_api`) para evitar doble superficie.

### Phase 2 - Recall Cleanup / Archive
Status: **DONE**
- [x] Legacy patch/diagnostic scripts removed from active runtime surface.
- [x] Legacy docs/scripts removed from workspace active scope.
- [x] Manual validation scripts removed from root active scope.
- [x] Legacy frontend/runtime artifacts removed (`App_Secure.tsx`, `backend/main.py`, `backend/cerberus_pro_api.py`, `backend/cerberus_ci.py`, `backend.log`, source export artifacts).
- [x] Runtime log/caches/build artifacts cleaned (`backend/logs`, `history` temp outputs, `dist`, `node_modules`, `sqlmap-master`, `__pycache__`).
- [x] Manifest + deprecation docs published.

### Phase 3 - Guardrails & CI
Status: **DONE**
- [x] `tools/recall_guard.py` implemented.
- [x] `tools/deprecation_guard.py` implemented.
- [x] CI workflow `recall-guard.yml` running guard checks + smoke tests.
- [x] `pytest.ini` added for stable local/CI imports.
- [x] Guardrails now validate canonical runtime target in Docker + Compose + launcher.
- [x] Guardrails bloquean reintroducción de `scan_router` legacy dentro de `ares_api`.

### Phase 4 - Reliability Fixes
Status: **DONE**
- [x] `test_system_sync` stabilized (mocked external-heavy paths).
- [x] `ScanManager` bugfix (`parameter` vs `param`) in escalation path.
- [x] Legacy root import shim removed; tests now import canonical backend module path.

### Phase 5 - Deprecation Sweep (Runtime)
Status: **DONE (runtime)** / **PARTIAL (full repo)**
- [x] Pydantic v2 migration on critical files (`field_validator`, `ConfigDict`).
- [x] Runtime UTC migration (`datetime.now(timezone.utc)` in backend runtime paths).
- [x] CI guard blocks reintroduction of deprecated patterns.
- [ ] Non-runtime folders (tests/archive) intentionally not enforced.

### Phase 6 - Frontend Load/UX Optimization
Status: **DONE (scope V1)**
- [x] Dynamic import for PDF engine (`jspdf`).
- [x] Vite manual chunking configured.
- [x] Lazy-loaded heavy UI panels (`AttackMap`, `StatsPanel`, `FingerprintView`, `ReportPanel`).
- [x] `TabbedView` renders active tab only.
- [x] Gemini module lazy-loaded + local fallback when no API key.
- [x] Frontend execution flow armonizado con backend unificado (`/scan/start|stop|status|capabilities`).
- [x] Eliminado dualismo `classic`/`omni` en control principal (single pipeline semantics).

## Current Quality Gates
- `npm run guard:recall` -> PASS
- `npm run guard:deprecations` -> PASS
- `pytest backend/tests/test_recall_route_surface.py -q` -> PASS
- `pytest backend/tests/test_system_sync.py -q` -> PASS
- `pytest backend/tests/test_worker_integration.py -q` -> PASS
- `pytest backend/tests/test_coverage_api_v1.py -q` -> PASS
- `npm run build` -> PASS
- `npm test` -> PASS

## Next Milestones (Execution Order)
1. **Hard cleanup (optional, non-functional)**
   - Move dormant legacy helper functions out of `backend/ares_api.py`.
   - Remove compatibility artifacts after operator sign-off.
2. **Operational visibility (optional)**
   - Add `/status/runtime` endpoint with guard/version/build info.
   - Surface guard status in UI admin panel.

## Definition of Done (Recall V1 Closure)
- Canonical backend only (no legacy runtime ambiguity).
- Guardrails enforced in CI for routes + deprecations.
- No false “dead feature” behavior in Analysis tab without API key.
- Stable smoke test suite green.
- Documented operational runbook and release checklist.
