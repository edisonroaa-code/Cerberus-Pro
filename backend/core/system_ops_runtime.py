"""
System operational status helpers extracted from ares_api.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List


@dataclass
class SystemOpsRuntimeDeps:
    state: Any
    environment: str
    job_queue_backend: str
    embedded_job_worker: bool
    worker_id: str
    version: str
    security_label: str
    job_count_db_fn: Callable[..., Awaitable[int]]
    ensure_job_background_tasks_fn: Callable[..., Awaitable[List[str]]]
    enqueue_queued_jobs_fn: Callable[[], Awaitable[None]]
    task_runtime_state_fn: Callable[[Any], dict]


def _jobs_runtime_snapshot(
    *,
    deps: SystemOpsRuntimeDeps,
    queued_db: int,
    running_db: int,
    started: List[str],
    requeued: bool,
    force_start: bool | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "backend_configured": deps.job_queue_backend,
        "backend_active": ("redis" if deps.state.redis is not None else "memory"),
        "embedded_worker_enabled": deps.embedded_job_worker,
        "worker_id": deps.worker_id,
        "db": {"queued": queued_db, "running": running_db},
        "memory_queue_depth": (deps.state.job_queue.qsize() if deps.state.redis is None else None),
        "tasks": {
            "job_worker": deps.task_runtime_state_fn(deps.state.job_worker_task),
            "queue_reconciler": deps.task_runtime_state_fn(deps.state.queue_reconciler_task),
        },
        "self_heal": {"started": started, "requeued": requeued},
    }
    if force_start is not None:
        payload["self_heal"]["force_start"] = bool(force_start)
    return payload


async def health_payload(*, deps: SystemOpsRuntimeDeps) -> Dict[str, Any]:
    queued_db = 0
    running_db = 0
    try:
        queued_db = await deps.job_count_db_fn(statuses=["queued"])
        running_db = await deps.job_count_db_fn(statuses=["running"])
    except Exception:
        queued_db = -1
        running_db = -1

    started: List[str] = []
    try:
        started = await deps.ensure_job_background_tasks_fn()
    except Exception:
        started = []

    requeued = False
    try:
        if deps.state.redis is None and queued_db > 0 and deps.state.job_queue.qsize() == 0:
            await deps.enqueue_queued_jobs_fn()
            requeued = True
    except Exception:
        requeued = False

    return {
        "status": "healthy",
        "version": deps.version,
        "security": deps.security_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "jobs": _jobs_runtime_snapshot(
            deps=deps,
            queued_db=queued_db,
            running_db=running_db,
            started=started,
            requeued=requeued,
        ),
    }


async def admin_kick_jobs_payload(*, deps: SystemOpsRuntimeDeps, force_start: bool = False) -> Dict[str, Any]:
    started = await deps.ensure_job_background_tasks_fn(force=bool(force_start))
    await deps.enqueue_queued_jobs_fn()
    queued_db = await deps.job_count_db_fn(statuses=["queued"])
    running_db = await deps.job_count_db_fn(statuses=["running"])
    return {
        "ok": True,
        "jobs": _jobs_runtime_snapshot(
            deps=deps,
            queued_db=queued_db,
            running_db=running_db,
            started=started,
            requeued=True,
            force_start=bool(force_start),
        ),
    }


def status_payload(*, deps: SystemOpsRuntimeDeps) -> Dict[str, Any]:
    return {
        "users_online": len([u for u in deps.state.users.values() if u.is_active]),
        "active_scans": len(deps.state.active_scans),
        "audit_logs": len(deps.state.audit_logs),
        "websocket_connections": len(deps.state.websocket_clients),
        "environment": deps.environment,
        "security_level": deps.security_label.upper(),
    }

