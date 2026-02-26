# Integration Matrix + Organigrama V1

Date: 2026-02-17  
Scope: runtime code only (`backend/*`, excluding `backend/archive/*`)

## Legend
- `ACTIVE`: connected to the unified runtime path and used in production flow.
- `BRIDGE`: connected indirectly, fallback, or compatibility path; keep until full consolidation.
- `CANDIDATE_REMOVE`: not connected to unified flow; archive only (no hard delete yet).

## Organigrama (real wiring today)
```text
Ares Runtime API (backend/ares_api.py)
|
|-- Job Queue + Worker Loop [ACTIVE]
|   |-- _job_worker_loop
|   `-- _run_job_by_kind -> _run_unified_multilevel_job
|
|-- Unified Multilevel Runner [ACTIVE]
|   |-- Config normalization
|   |   |-- classic -> unified web config
|   |   `-- omni -> normalized mode config
|   |
|   |-- Policy Gate [ACTIVE]
|   |   `-- validate_target / validate_network_host + governance policy_engine
|   |
|   |-- Orchestrator FSM [ACTIVE]
|   |   `-- preflight -> discovery -> execution -> escalation -> correlation -> verdict
|   |
|   |-- Execution Web/GraphQL [ACTIVE]
|   |   `-- run_omni_surface_scan
|   |       |-- sqlmap vectors
|   |       |-- AIIE / NOSQL / SSTI engines (engine_registry)
|   |       |-- EngineOrchestrator adapters (when `engine_scan_enabled=true`)
|   |       `-- coverage + verdict contract v1
|   |
|   `-- Execution Non-Web [ACTIVE]
|       `-- direct_db / ws / mqtt / grpc handled inside unified runner
|
|-- Coverage/Report Contract [ACTIVE]
|   |-- issue_verdict_v1
|   |-- CoverageResponseV1 persistence
|   `-- GET /api/v1/jobs/{scan_id}/coverage
|
|-- Offensive side subsystems (API endpoints) [ACTIVE but parallel subsystem]
|   |-- Metasploit bridge endpoints
|   |-- C2 server endpoints
|   |-- Exfil listeners endpoints
|   |-- Payload generation endpoints
|   `-- PrivEsc endpoints
|
`-- Legacy execution path still present in file [BRIDGE]
    |-- _run_classic_job
    |-- _run_omni_job
    |-- scan_reader_task
    `-- start_next_phase
```

## Integration Matrix

| Domain | Module | Current Status | Unified Runner Connected | Evidence | Action |
|---|---|---|---|---|---|
| Runtime entrypoint | `backend/ares_api.py` | `ACTIVE` | Yes | `backend/ares_api.py:1074`, `backend/ares_api.py:1141` | Keep as single runtime authority |
| Compatibility facade | `backend/cerberus_pro_api_secure.py` | `BRIDGE` | Indirect | Loaded as compatibility layer; canonical runtime remains `ares_api` | Keep until all external imports are migrated |
| Unified job dispatch | `_run_job_by_kind` -> `_run_unified_multilevel_job` | `ACTIVE` | Yes | `backend/ares_api.py:1141`, `backend/ares_api.py:1074` | Keep |
| Classic normalization | `_normalize_classic_to_unified_cfg` | `ACTIVE` | Yes | `backend/ares_api.py:993` | Keep; continue replacing legacy classic path |
| Policy gate | `_validate_unified_target_policy` | `ACTIVE` | Yes | `backend/ares_api.py:1038` | Keep; centralize all policy checks here |
| FSM orchestration | `core/orchestrator_fsm.py` | `ACTIVE` | Yes | `backend/ares_api.py:121`, `backend/ares_api.py:1123` | Keep |
| Web execution engine | `run_omni_surface_scan` + `v4_omni_surface` | `ACTIVE` | Yes | `backend/ares_api.py:1113`, `backend/ares_api.py:2520`, `backend/ares_api.py:90` | Keep as execution core |
| Coverage + verdict | `core/coverage_contract_v1.py`, `issue_verdict_v1` | `ACTIVE` | Yes | `backend/ares_api.py:110`, `backend/ares_api.py:3028`, `backend/ares_api.py:3718` | Keep as single verdict contract |
| Coverage API | `GET /api/v1/jobs/{scan_id}/coverage` | `ACTIVE` | Yes | `backend/ares_api.py:4191` | Keep |
| Non-web unified execution | `run_omni_surface_scan` (`direct_db`, `ws`, `mqtt`, `grpc`) | `ACTIVE` | Yes | non-web handled directly in unified runner (no `ScanManager` fallback) | Keep |
| Engine orchestrator | `engines/orchestrator.py` | `ACTIVE` | Yes (conditional) | `backend/ares_api.py:2632`, `backend/ares_api.py:2652`, `backend/ares_api.py:2916` | Keep as unified engine layer |
| Engine adapters | `engines/*_adapter.py` | `ACTIVE` | Yes (via `EngineOrchestrator`) | `backend/ares_api.py:2916`, `backend/engines/__init__.py:27` | Keep; continue hardening adapter contracts |
| Governance policy engine | `governance/policy_engine.py` | `ACTIVE` | Yes | `backend/ares_api.py` unified policy gate + escalation policy checks | Keep as single policy authority |
| WAF detective | `core/waf_detective.py` | `BRIDGE` | Indirect | used in `engines/orchestrator.py` and `scan_manager.py`; web path uses `calibration_waf_detect` | Consolidate WAF logic to one service |
| Chain orchestration v1 | `core/chain_orchestrator.py` | `ACTIVE` (discovery mode) | Yes (unified escalation phase) | unified runner `ESCALATION` uses chain discovery + policy gating | Keep; extend carefully if active execution is ever enabled |
| Chain orchestration v2 | `core/chain_orchestrator_v2.py` | `BRIDGE` | Indirect | via `engines/orchestrator.py:179` | Keep until chain strategy is finalized |
| Offensive sandbox runner | `offensiva/sandbox_runner.py` | `ACTIVE` (compat layer) | Yes | delegates to core sandbox runner with API compatibility | Keep as compatibility layer |
| Core sandbox runner | `core/sandbox_runner.py` | `ACTIVE` (canonical) | Yes | canonical implementation shared by offensive/core paths | Keep as canonical sandbox |
| Lateral movement module | `offensiva/lateral_movement.py` | `BRIDGE` | Via chain orchestrator only | `backend/core/chain_orchestrator.py:536` | Integrate as controlled phase in unified pipeline |
| Evidence exfil module | `offensiva/evidence_exfil.py` | `BRIDGE` | Not yet wired in unified scan path | no direct call from `ares_api.py` unified scan flow | Preserve and integrate in explicit escalation phase |
| Legacy classic executor | `_run_classic_job` | `BRIDGE` | Not used by dispatcher now | `backend/ares_api.py:1152` | Remove after full stop/status migration and smoke tests |
| Legacy omni executor | `_run_omni_job` | `BRIDGE` | Not used by dispatcher now | `backend/ares_api.py:1252` | Remove after full stop/status migration and smoke tests |
| Legacy reader/autopilot loop | `scan_reader_task`, `start_next_phase` | `BRIDGE` | Not used by unified dispatcher | `backend/ares_api.py:3446`, `backend/ares_api.py:3971` | Remove after report parity tests pass |
| Offensive endpoint subsystem | Metasploit/C2/Exfil/Payload/PrivEsc endpoints | `ACTIVE` | Parallel subsystem (not part of scan pipeline) | `backend/ares_api.py:4475`, `backend/ares_api.py:4535`, `backend/ares_api.py:4616`, `backend/ares_api.py:4685`, `backend/ares_api.py:4707` | Keep; optional later integration into unified stage model |

## Safe Removal Gate (must pass before hard delete)
1. Unified runner handles all modes (`web`, `graphql`, `direct_db`, `ws`, `mqtt`, `grpc`) without `ScanManager` fallback. ✅
2. `engine_scan_enabled` executes adapters through one unified execution branch. ✅
3. Escalation remains discovery/planning by default with strict policy gating. ✅
4. Legacy execution helpers are not on active dispatch path (hard removal optional). ✅
5. Stop/status endpoints work through job/task abstraction for active runtime. ✅

## Next Integration Sprint (recommended order)
1. Optional hard cleanup: move dormant legacy helper functions out of `backend/ares_api.py`.
2. Optional hard cleanup: purge archive debt after operator sign-off.
3. Keep CI guardrails enforcing unified runtime path.
