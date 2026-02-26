"""
Job persistence/runtime helpers extracted from ares_api.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from core.coverage_contract_v1 import (
    COVERAGE_SCHEMA_VERSION_V1,
    CoverageResponseV1,
    CoverageSummaryV1,
    adapt_legacy_blockers,
    issue_verdict_v1,
)


@dataclass
class JobPersistenceRuntimeDeps:
    pg_enabled_fn: Callable[[], bool]
    pg_store: Any
    jobs_db_path: str
    normalize_job_kind_fn: Callable[[Any], str]
    normalize_unified_scan_cfg_fn: Callable[[dict], dict]
    read_unified_runtime_cfg_fn: Callable[[dict], dict]
    persist_scan_artifacts_db_fn: Callable[..., None]
    sqlite_create_job_fn: Callable[..., None]
    sqlite_update_job_fn: Callable[..., None]
    sqlite_get_job_fn: Callable[..., Optional[dict]]
    sqlite_list_jobs_fn: Callable[..., List[dict]]
    build_default_vector_page_fn: Callable[[int, int], Any]
    logger: Any


def create_job(
    *,
    scan_id: str,
    user_id: str,
    kind: str,
    status: str,
    phase: int,
    max_phase: int,
    autopilot: bool,
    target_url: str,
    cfg: dict,
    deps: JobPersistenceRuntimeDeps,
    job_now_fn: Callable[[], str],
    pid: Optional[int] = None,
    priority: int = 0,
) -> None:
    normalized_kind = deps.normalize_job_kind_fn(kind)
    normalized_cfg = deps.normalize_unified_scan_cfg_fn(cfg or {})
    if deps.pg_enabled_fn():
        deps.pg_store.create_job(
            scan_id=scan_id,
            user_id=user_id,
            kind=normalized_kind,
            status=status,
            phase=phase,
            max_phase=max_phase,
            autopilot=autopilot,
            target_url=target_url,
            cfg=normalized_cfg,
            pid=pid,
            priority=priority,
        )
        deps.persist_scan_artifacts_db_fn(
            scan_id=str(scan_id),
            user_id=str(user_id),
            kind=normalized_kind,
            target_url=str(target_url or ""),
            mode=(str((normalized_cfg or {}).get("mode")) if (normalized_cfg or {}).get("mode") else None),
            profile=(
                str((normalized_cfg or {}).get("profile"))
                if (normalized_cfg or {}).get("profile") is not None
                else None
            ),
            status=str(status),
            verdict=None,
            conclusive=None,
            vulnerable=None,
            count=None,
            evidence_count=None,
            results_count=None,
            message=None,
            cfg=normalized_cfg,
            coverage={},
            report_data={},
        )
        return
    created_at = job_now_fn()
    deps.sqlite_create_job_fn(
        deps.jobs_db_path,
        scan_id=scan_id,
        user_id=user_id,
        kind=normalized_kind,
        status=status,
        phase=int(phase),
        max_phase=int(max_phase),
        autopilot=autopilot,
        target_url=str(target_url),
        cfg=normalized_cfg,
        created_at=created_at,
        started_at=(created_at if status == "running" else None),
        pid=pid,
        priority=int(priority),
    )


def get_job(scan_id: str, *, deps: JobPersistenceRuntimeDeps) -> Optional[dict]:
    if deps.pg_enabled_fn():
        job = deps.pg_store.get_job(scan_id)
        if not job:
            return None
        job["kind"] = deps.normalize_job_kind_fn(job.get("kind"))
        job["config"] = deps.normalize_unified_scan_cfg_fn(job.get("config") or {})
        return job
    out = deps.sqlite_get_job_fn(deps.jobs_db_path, scan_id=str(scan_id))
    if not out:
        return None
    out["kind"] = deps.normalize_job_kind_fn(out.get("kind"))
    out["config"] = deps.normalize_unified_scan_cfg_fn(out.get("config") or {})
    return out


def update_job(
    scan_id: str,
    *,
    deps: JobPersistenceRuntimeDeps,
    fields: Dict[str, Any],
) -> None:
    if not fields:
        return
    allowed = {
        "status",
        "started_at",
        "finished_at",
        "phase",
        "max_phase",
        "pid",
        "worker_id",
        "heartbeat_at",
        "attempts",
        "priority",
        "result_filename",
        "vulnerable",
        "error",
        "config_json",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    if deps.pg_enabled_fn():
        deps.pg_store.update_job(scan_id, updates)
        try:
            job = get_job(scan_id, deps=deps) or {}
            deps.persist_scan_artifacts_db_fn(
                scan_id=str(scan_id),
                user_id=str(job.get("user_id") or ""),
                kind=str(job.get("kind") or ""),
                target_url=str(job.get("target_url") or ""),
                mode=(str((job.get("config") or {}).get("mode")) if (job.get("config") or {}).get("mode") else None),
                profile=(
                    str((job.get("config") or {}).get("profile"))
                    if (job.get("config") or {}).get("profile") is not None
                    else None
                ),
                status=str(job.get("status") or updates.get("status") or "queued"),
                verdict=None,
                conclusive=None,
                vulnerable=(bool(job.get("vulnerable")) if job.get("vulnerable") is not None else None),
                count=None,
                evidence_count=None,
                results_count=None,
                message=(str(job.get("error")) if job.get("error") else None),
                cfg=(job.get("config") or {}),
                coverage={},
                report_data={},
            )
        except Exception:
            pass
        return
    deps.sqlite_update_job_fn(deps.jobs_db_path, scan_id=str(scan_id), updates=updates)


def list_jobs(user_id: str, *, limit: int, deps: JobPersistenceRuntimeDeps) -> List[dict]:
    if deps.pg_enabled_fn():
        rows = deps.pg_store.list_jobs(user_id=user_id, limit=limit)
        for row in rows:
            row["kind"] = deps.normalize_job_kind_fn(row.get("kind"))
        return rows
    rows = deps.sqlite_list_jobs_fn(deps.jobs_db_path, user_id=str(user_id), limit=int(limit))
    for row in rows:
        row["kind"] = deps.normalize_job_kind_fn(row.get("kind"))
    return rows


def fallback_coverage_response_from_job(
    job: Dict[str, Any],
    scan_id: str,
    *,
    limit: int,
    cursor: int,
    deps: JobPersistenceRuntimeDeps,
) -> CoverageResponseV1:
    requested_engines: List[str] = []
    cfg = deps.normalize_unified_scan_cfg_fn(job.get("config") if isinstance(job.get("config"), dict) else {})
    mode = str((cfg or {}).get("mode") or "web").lower()
    unified_cfg = deps.read_unified_runtime_cfg_fn(cfg)
    if mode in {"web", "graphql"}:
        requested_engines = [str(v).upper() for v in (unified_cfg.get("vectors") or []) if str(v).strip()]
        if not requested_engines:
            requested_engines = ["SQLMAP"]
    else:
        requested_engines = [mode.upper()]
    summary = CoverageSummaryV1(
        coverage_percentage=0.0,
        engines_requested=requested_engines,
        engines_executed=[],
        inputs_found=0,
        inputs_tested=0,
        inputs_failed=0,
        deps_missing=[],
        preflight_ok=False,
        execution_ok=False,
        verdict_phase_completed=False,
        status=str(job.get("status") or "unknown"),
        total_duration_ms=0,
        redactions_applied=True,
    )
    blockers = adapt_legacy_blockers(
        [
            {
                "code": "coverage_incomplete",
                "message": "Cobertura aún no disponible para este scan",
                "detail": {"reason": "coverage_not_persisted_yet", "job_status": job.get("status")},
                "phase": "verdict",
                "recoverable": True,
            }
        ],
        default_phase="verdict",
    )
    requested_verdict = "VULNERABLE" if bool(job.get("vulnerable")) else "INCONCLUSIVE"
    decision = issue_verdict_v1(
        has_confirmed_finding=bool(job.get("vulnerable")),
        requested_verdict=requested_verdict,
        summary=summary,
        blockers=blockers,
    )
    return CoverageResponseV1(
        version=COVERAGE_SCHEMA_VERSION_V1,
        scan_id=str(scan_id),
        job_status=str(job.get("status") or "unknown"),
        verdict=decision.verdict,
        conclusive=decision.conclusive,
        vulnerable=decision.vulnerable,
        coverage_summary=summary,
        conclusive_blockers=decision.blockers,
        phase_records=[],
        vector_records_page=deps.build_default_vector_page_fn(limit=limit, cursor=cursor),
    )


def get_job_coverage_v1(
    scan_id: str,
    *,
    limit: int,
    cursor: int,
    deps: JobPersistenceRuntimeDeps,
) -> Optional[CoverageResponseV1]:
    if deps.pg_enabled_fn():
        try:
            raw = deps.pg_store.get_coverage_v1(scan_id=str(scan_id), limit=limit, cursor=cursor)
            if raw:
                if str(raw.get("version") or "").strip() != COVERAGE_SCHEMA_VERSION_V1:
                    raw["version"] = COVERAGE_SCHEMA_VERSION_V1
                raw["scan_id"] = str(scan_id)
                return CoverageResponseV1.model_validate(raw)
        except Exception as exc:
            deps.logger.warning(f"Coverage retrieval failed for {scan_id}: {exc}")
    return None

