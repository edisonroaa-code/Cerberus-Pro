"""
PostgreSQL/SQLite persistence helpers extracted from ares_api.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, List, Optional


@dataclass
class PostgresPersistenceRuntimeDeps:
    pg_store: Any
    jobs_db_path: str
    job_running_stale_seconds: int
    logger: Any
    normalize_job_kind_fn: Callable[[Any], str]
    job_kind_candidates_fn: Callable[[Any], List[str]]
    job_now_fn: Callable[[], str]
    jobs_sqlite_count_jobs_fn: Callable[..., int]
    jobs_sqlite_latest_active_scan_id_fn: Callable[..., Optional[str]]
    jobs_sqlite_recover_running_jobs_fn: Callable[..., None]


def pg_enabled(deps: PostgresPersistenceRuntimeDeps) -> bool:
    return deps.pg_store is not None


def job_count_db(
    deps: PostgresPersistenceRuntimeDeps,
    *,
    user_id: Optional[str] = None,
    statuses: Optional[List[str]] = None,
) -> int:
    if pg_enabled(deps):
        try:
            return int(deps.pg_store.count_jobs(user_id=user_id, statuses=statuses))
        except Exception:
            return 0
    return deps.jobs_sqlite_count_jobs_fn(deps.jobs_db_path, user_id=user_id, statuses=statuses)


def job_latest_active_scan_id(
    deps: PostgresPersistenceRuntimeDeps,
    *,
    user_id: str,
    kind: str,
) -> Optional[str]:
    kinds = deps.job_kind_candidates_fn(kind)
    if pg_enabled(deps):
        try:
            return deps.pg_store.latest_active_job_scan_id(user_id=str(user_id), kinds=kinds)
        except Exception:
            return None
    return deps.jobs_sqlite_latest_active_scan_id_fn(deps.jobs_db_path, user_id=str(user_id), kinds=kinds)


def persist_scan_artifacts_db(
    deps: PostgresPersistenceRuntimeDeps,
    *,
    scan_id: str,
    user_id: str,
    kind: str,
    target_url: str,
    mode: Optional[str],
    profile: Optional[str],
    status: str,
    verdict: Optional[str],
    conclusive: Optional[bool],
    vulnerable: Optional[bool],
    count: Optional[int],
    evidence_count: Optional[int],
    results_count: Optional[int],
    message: Optional[str],
    cfg: Optional[dict],
    coverage: Optional[dict],
    report_data: Optional[dict],
) -> None:
    if (not pg_enabled(deps)) or (not scan_id):
        return
    normalized_kind = deps.normalize_job_kind_fn(kind)
    try:
        deps.pg_store.persist_scan_artifacts(
            scan_id=str(scan_id),
            user_id=str(user_id),
            kind=normalized_kind,
            target_url=str(target_url or ""),
            mode=(str(mode) if mode else None),
            profile=(str(profile) if profile else None),
            status=str(status),
            verdict=(str(verdict) if verdict else None),
            conclusive=conclusive,
            vulnerable=vulnerable,
            count=count,
            evidence_count=evidence_count,
            results_count=results_count,
            message=(str(message) if message else None),
            cfg=cfg or {},
            coverage=coverage or {},
            report_data=report_data or {},
            finished_at=deps.job_now_fn(),
        )
    except Exception as exc:
        deps.logger.warning("PostgreSQL artifacts persistence failed for %s: %s", scan_id, exc)


def persist_coverage_v1_db(deps: PostgresPersistenceRuntimeDeps, coverage_response: Any) -> None:
    if not pg_enabled(deps):
        return
    try:
        deps.pg_store.persist_coverage_v1(
            scan_id=coverage_response.scan_id,
            version=coverage_response.version,
            job_status=coverage_response.job_status,
            verdict=coverage_response.verdict,
            conclusive=coverage_response.conclusive,
            vulnerable=coverage_response.vulnerable,
            coverage_summary=coverage_response.coverage_summary.model_dump(),
            conclusive_blockers=[b.model_dump() for b in coverage_response.conclusive_blockers],
            phase_records=[p.model_dump() for p in coverage_response.phase_records],
            vector_records=[v.model_dump(exclude={"id"}) for v in coverage_response.vector_records_page.items],
        )
    except Exception as exc:
        deps.logger.warning(
            "PostgreSQL coverage.v1 persistence failed for %s: %s",
            coverage_response.scan_id,
            exc,
        )


def jobs_recover_on_startup(deps: PostgresPersistenceRuntimeDeps) -> None:
    if pg_enabled(deps):
        try:
            deps.pg_store.recover_running_jobs(stale_seconds=deps.job_running_stale_seconds)
            return
        except Exception as exc:
            deps.logger.warning(
                "PostgreSQL recover-on-startup failed, falling back to SQLite: %s",
                exc,
            )
    deps.jobs_sqlite_recover_running_jobs_fn(
        deps.jobs_db_path,
        stale_seconds=deps.job_running_stale_seconds,
        now_iso=deps.job_now_fn(),
    )
