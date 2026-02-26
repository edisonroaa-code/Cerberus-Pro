# Recall Manifest V1 (Cerberus -> Ares Core)

Date: 2026-02-17  
Owner: Core refactor stream

## Objective
Consolidate the platform into one solid orchestrated core, remove dead/legacy clutter, and keep only production-useful code paths.

## Canonical Runtime
- API entrypoint (canonical implementation): `backend/ares_api.py`
- Compatibility entrypoint (stable import target): `backend/cerberus_pro_api_secure.py`
- Frontend runtime: `App.tsx` + `services/*`

## Classification (Initial Pass)

### KEEP (Runtime-critical)
- `backend/ares_api.py`
- `backend/core/*` (coverage, verdict, orchestrator, dependencies)
- `backend/db/*`
- `backend/engines/*`
- `backend/routers/*` (except legacy overlaps)
- `backend/services/*` (runtime-used only)
- `backend/tests/*` (valid regression suite)
- `tools/dev-all.mjs`, `tools/smoke_jobs.py`, `tools/ws_smoke.py`
- `App.tsx`, `components/*`, `services/*`

### REWRITE / CONSOLIDATE
- `backend/cerberus_pro_api_secure.py`
  - Keep as proxy/compatibility module only.
  - No business logic duplication allowed.
- `backend/routers/scan.py`
  - Avoid route overlap with canonical secure API.
- `backend/intel/cve_ingester.py`
  - Replace mock-only behavior with live provider + cache/fallback policy.
- `backend/v4_omni_surface.py`
  - Reduce vector runtime complexity and enforce deterministic budgets.

### REMOVE / ARCHIVE CANDIDATES (after final dependency check)
- `backend/patch_api.py`
- `backend/patch_api_2026.py`
- `backend/patch_api_stability.py`
- `backend/tmp_cors_patch.py`
- `backend/verify_v4_omni.py`
- `backend/verify_2026_evasion.py`
- `backend/diagnostic_v4.py`
- `backend/example_integration.py` (archive if not used in CI/runtime)

## Hard Rules For This Recall
1. One source of truth for verdict (`ares_api` backend only).
2. One contract for coverage/blockers/verdict across backend->DB->frontend.
3. No duplicate route semantics.
4. No patch scripts in runtime path.
5. No module survives without usage proof or tests.

## Migration Steps (Execution Order)
1. Freeze new feature additions.
2. Build usage map (imports, routes, scripts, CI references).
3. Move/archive dead scripts to `backend/archive/`.
4. Tighten tests around canonical API behavior.
5. Remove archived modules from docs and startup scripts.
6. Publish v1 architecture docs and deprecation list.

## Progress (Executed)
- [x] Compatibility facade hardened: `backend/cerberus_pro_api_secure.py` proxies to canonical `backend/ares_api.py`.
- [x] Legacy patch/verify/tmp scripts moved to `backend/archive/legacy_tools/`.
- [x] Canonical runtime commands switched to `backend.ares_api:app` (`package.json`, `tools/dev-all.mjs`).
- [x] Frontend removed legacy `/start` and `/stop` fallbacks.
- [x] Route collision mitigated (`/scan/module/status` in modular router).
- [x] Route-surface regression tests added: `backend/tests/test_recall_route_surface.py`.
- [x] CI guardrail added: `tools/recall_guard.py` + `.github/workflows/recall-guard.yml`.
- [x] System sync smoke test stabilized and added to recall CI: `backend/tests/test_system_sync.py`.
- [x] Deprecation sweep started (UTC-aware datetimes + Pydantic v2 migration) with CI guard: `tools/deprecation_guard.py`.
- [x] Runtime containers/launcher aligned to canonical entrypoint (`backend.ares_api:app`).
- [x] Manual validation scripts removed from backend root and archived (`backend/archive/manual_validation/`).

## Exit Criteria
- All runtime commands start from canonical modules only.
- No duplicate API endpoints with conflicting request models.
- Tests pass for scan/jobs/coverage/verdict contract.
- Frontend receives normalized errors (no `[object Object]`).
