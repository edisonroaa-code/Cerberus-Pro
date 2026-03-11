"""
Queue/worker bridge runtime extracted from ares_api.py.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List, Optional


@dataclass
class JobQueueBridgeDeps:
    state: Any
    logger: Any
    worker_id: str
    embedded_job_worker: bool
    job_queue_backend: str
    redis_available: bool
    redis_module: Any
    redis_url: str
    queue_key: str
    queue_reconcile_seconds: int
    queue_backlog_metric: Any
    pg_store: Any
    jobs_db_path: str
    pg_enabled_fn: Callable[[], bool]
    job_count_db_fn: Callable[..., int]
    job_get_fn: Callable[[str], Awaitable[Optional[dict]]]
    job_now_fn: Callable[[], str]
    job_update_fn: Callable[..., Awaitable[None]]
    normalize_job_kind_fn: Callable[[Any], str]
    run_job_by_kind_fn: Callable[[str, str, str, dict], Awaitable[None]]
    heartbeat_loop_fn: Callable[[str], Awaitable[None]]
    init_audit_db_fn: Callable[[], None]
    init_jobs_db_fn: Callable[[], None]
    jobs_recover_on_startup_fn: Callable[[], None]
    jobs_sqlite_list_queued_job_ids_fn: Callable[[str], List[str]]
    runtime_init_job_queue_backend_fn: Callable[..., Awaitable[None]]
    runtime_refresh_queue_backlog_metric_fn: Callable[..., Awaitable[None]]
    runtime_queue_enqueue_fn: Callable[..., Awaitable[None]]
    runtime_enqueue_job_memory_fn: Callable[..., None]
    runtime_queue_pop_fn: Callable[..., Awaitable[Optional[str]]]
    runtime_queue_reconciler_loop_fn: Callable[..., Awaitable[None]]
    runtime_task_runtime_state_fn: Callable[[Optional[asyncio.Task]], dict]
    runtime_ensure_job_background_tasks_fn: Callable[..., Awaitable[List[str]]]
    worker_runner_run_standalone_worker_fn: Callable[..., Awaitable[None]]
    worker_loop_impl_fn: Callable[..., Awaitable[None]]


async def init_job_queue_backend(deps: JobQueueBridgeDeps) -> None:
    await deps.runtime_init_job_queue_backend_fn(
        state=deps.state,
        job_queue_backend=deps.job_queue_backend,
        redis_available=deps.redis_available,
        redis_module=deps.redis_module,
        redis_url=deps.redis_url,
        worker_id=deps.worker_id,
        logger=deps.logger,
    )


async def refresh_queue_backlog_metric(deps: JobQueueBridgeDeps) -> None:
    await deps.runtime_refresh_queue_backlog_metric_fn(
        pg_enabled=deps.pg_enabled_fn(),
        pg_store=deps.pg_store,
        job_count_db=deps.job_count_db_fn,
        queue_backlog_metric=deps.queue_backlog_metric,
    )


def enqueue_job_memory(scan_id: str, deps: JobQueueBridgeDeps) -> None:
    deps.runtime_enqueue_job_memory_fn(
        state=deps.state,
        queue_backlog_metric=deps.queue_backlog_metric,
        scan_id=scan_id,
    )


async def queue_enqueue(scan_id: str, *, priority: int, deps: JobQueueBridgeDeps) -> None:
    await deps.runtime_queue_enqueue_fn(
        state=deps.state,
        scan_id=scan_id,
        priority=int(priority),
        job_get=deps.job_get_fn,
        job_now=deps.job_now_fn,
        queue_key=deps.queue_key,
        refresh_queue_backlog_metric_fn=lambda: refresh_queue_backlog_metric(deps),
        enqueue_job_memory_fn=lambda sid: enqueue_job_memory(sid, deps),
    )


async def enqueue_queued_jobs(deps: JobQueueBridgeDeps) -> None:
    if deps.pg_enabled_fn():
        try:
            queued_ids = deps.pg_store.list_job_ids_by_status("queued")
        except Exception as exc:
            deps.logger.warning(
                "PostgreSQL queue sync failed, falling back to SQLite: %s",
                exc,
            )
            queued_ids = []
    else:
        queued_ids = deps.jobs_sqlite_list_queued_job_ids_fn(deps.jobs_db_path)

    for scan_id in queued_ids:
        try:
            job = await deps.job_get_fn(str(scan_id)) or {}
            await queue_enqueue(str(scan_id), priority=int(job.get("priority") or 0), deps=deps)
        except Exception:
            continue


async def queue_pop(timeout_seconds: int, deps: JobQueueBridgeDeps) -> Optional[str]:
    return await deps.runtime_queue_pop_fn(
        state=deps.state,
        timeout_seconds=int(timeout_seconds),
        queue_key=deps.queue_key,
        queue_backlog_metric=deps.queue_backlog_metric,
        refresh_queue_backlog_metric_fn=lambda: refresh_queue_backlog_metric(deps),
    )


async def queue_reconciler_loop(deps: JobQueueBridgeDeps) -> None:
    await deps.runtime_queue_reconciler_loop_fn(
        reconcile_seconds=deps.queue_reconcile_seconds,
        enqueue_queued_jobs_fn=lambda: enqueue_queued_jobs(deps),
    )


def task_runtime_state(task: Optional[asyncio.Task], deps: JobQueueBridgeDeps) -> dict:
    return deps.runtime_task_runtime_state_fn(task)


async def ensure_job_background_tasks(force: bool, deps: JobQueueBridgeDeps) -> List[str]:
    return await deps.runtime_ensure_job_background_tasks_fn(
        state=deps.state,
        embedded_job_worker=deps.embedded_job_worker,
        force=bool(force),
        job_worker_loop_fn=lambda: job_worker_loop(deps),
        queue_reconciler_loop_fn=lambda: queue_reconciler_loop(deps),
    )


async def run_standalone_job_worker(
    *,
    stop_event: Optional[asyncio.Event],
    deps: JobQueueBridgeDeps,
) -> None:
    await deps.worker_runner_run_standalone_worker_fn(
        state=deps.state,
        logger=deps.logger,
        worker_id=deps.worker_id,
        job_queue_backend=deps.job_queue_backend,
        stop_event=stop_event,
        init_audit_db_fn=deps.init_audit_db_fn,
        init_jobs_db_fn=deps.init_jobs_db_fn,
        init_job_queue_backend_fn=lambda: init_job_queue_backend(deps),
        jobs_recover_on_startup_fn=deps.jobs_recover_on_startup_fn,
        enqueue_queued_jobs_fn=lambda: enqueue_queued_jobs(deps),
        ensure_job_background_tasks_fn=lambda force=False: ensure_job_background_tasks(force, deps),
    )


async def job_worker_loop(deps: JobQueueBridgeDeps) -> None:
    async def _queue_pop_bridge(timeout_seconds: int) -> Optional[str]:
        return await queue_pop(timeout_seconds=timeout_seconds, deps=deps)

    await deps.worker_loop_impl_fn(
        state=deps.state,
        queue_pop_fn=_queue_pop_bridge,
        job_get=deps.job_get_fn,
        normalize_job_kind=deps.normalize_job_kind_fn,
        job_update=deps.job_update_fn,
        job_now=deps.job_now_fn,
        worker_id=deps.worker_id,
        run_job_by_kind_fn=deps.run_job_by_kind_fn,
        heartbeat_loop_fn=deps.heartbeat_loop_fn,
    )
