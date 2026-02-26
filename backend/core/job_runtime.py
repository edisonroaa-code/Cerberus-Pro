"""
Job queue runtime helpers extracted from ares_api.py.

The API layer passes concrete dependencies (state, metrics, DB accessors) to
keep this module framework-light and reusable.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, List, Optional

from fastapi import HTTPException


async def init_job_queue_backend(
    *,
    state: Any,
    job_queue_backend: str,
    redis_available: bool,
    redis_module: Any,
    redis_url: str,
    worker_id: str,
    logger: Any,
) -> None:
    if job_queue_backend != "redis":
        return
    if not redis_available:
        logger.warning("JOB_QUEUE_BACKEND=redis requested but redis client not available; using memory queue")
        return
    try:
        state.redis = redis_module.from_url(redis_url, decode_responses=True)
        await state.redis.ping()
        logger.info("🧾 Job queue backend=redis connected worker_id=%s", worker_id)
    except Exception as exc:
        logger.warning("JOB_QUEUE_BACKEND=redis connect failed; using memory queue: %s", exc)
        state.redis = None


def job_score(priority: int, created_at_iso: str) -> float:
    # Lower score pops first. Higher priority should pop sooner.
    try:
        base = datetime.fromisoformat(created_at_iso).timestamp()
    except Exception:
        base = datetime.now(timezone.utc).timestamp()
    return float(base - (int(priority) * 1_000_000))


async def refresh_queue_backlog_metric(
    *,
    pg_enabled: bool,
    pg_store: Any,
    job_count_db: Callable[..., Awaitable[int]],
    queue_backlog_metric: Any,
) -> None:
    try:
        if pg_enabled:
            queued = int(await pg_store.count_jobs(statuses=["queued"]))
        else:
            queued = int(await job_count_db(statuses=["queued"]))
        queue_backlog_metric.set(max(0, queued))
    except Exception:
        return


def enqueue_job_memory(*, state: Any, queue_backlog_metric: Any, scan_id: str) -> None:
    try:
        state.job_queue.put_nowait(scan_id)
        queue_backlog_metric.set(max(0, state.job_queue.qsize()))
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="Job queue full; retry later")


async def queue_enqueue(
    *,
    state: Any,
    scan_id: str,
    priority: int,
    job_get: Callable[[str], Awaitable[Optional[dict]]],
    job_now: Callable[[], str],
    queue_key: str,
    refresh_queue_backlog_metric_fn: Callable[[], Awaitable[None]],
    enqueue_job_memory_fn: Callable[[str], None],
) -> None:
    if state.redis is None:
        enqueue_job_memory_fn(scan_id)
        await refresh_queue_backlog_metric_fn()
        return

    job = await job_get(scan_id)
    job = job or {}
    score = job_score(int(priority), str(job.get("created_at") or job_now()))
    # ZADD is idempotent for existing members.
    await state.redis.zadd(queue_key, {scan_id: score})
    await refresh_queue_backlog_metric_fn()


async def queue_pop(
    *,
    state: Any,
    timeout_seconds: int,
    queue_key: str,
    queue_backlog_metric: Any,
    refresh_queue_backlog_metric_fn: Callable[[], Awaitable[None]],
) -> Optional[str]:
    if state.redis is None:
        try:
            item = await asyncio.wait_for(state.job_queue.get(), timeout=timeout_seconds)
            queue_backlog_metric.set(max(0, state.job_queue.qsize()))
            await refresh_queue_backlog_metric_fn()
            return str(item)
        except asyncio.TimeoutError:
            return None

    try:
        res = await state.redis.bzpopmin(queue_key, timeout=timeout_seconds)
        if not res:
            return None
        # redis-py returns (key, member, score)
        _key, member, _score = res
        await refresh_queue_backlog_metric_fn()
        return str(member)
    except Exception:
        return None


async def queue_reconciler_loop(
    *,
    reconcile_seconds: int,
    enqueue_queued_jobs_fn: Callable[[], Awaitable[None]],
) -> None:
    # Ensures DB queued jobs are present in the queue backend. This helps recover
    # from instance crashes between dequeue and DB status update.
    while True:
        try:
            await asyncio.sleep(max(3, reconcile_seconds))
            await enqueue_queued_jobs_fn()
        except asyncio.CancelledError:
            raise
        except Exception:
            continue


def task_runtime_state(task: Optional[asyncio.Task]) -> dict:
    if not task:
        return {"present": False}
    data = {
        "present": True,
        "done": bool(task.done()),
        "cancelled": bool(task.cancelled()),
    }
    if task.done() and (not task.cancelled()):
        try:
            exc = task.exception()
        except Exception as err:
            exc = err
        data["exception"] = (repr(exc) if exc else None)
    return data


async def ensure_job_background_tasks(
    *,
    state: Any,
    embedded_job_worker: bool,
    force: bool,
    job_worker_loop_fn: Callable[[], Awaitable[None]],
    queue_reconciler_loop_fn: Callable[[], Awaitable[None]],
) -> List[str]:
    """
    Best-effort self-heal: ensure background tasks exist even if lifespan didn't
    run (misconfigured ASGI app) or a task crashed unexpectedly.
    """
    if (not embedded_job_worker) and (not force):
        return []

    started: List[str] = []
    if (not state.job_worker_task) or state.job_worker_task.done():
        state.job_worker_task = asyncio.create_task(job_worker_loop_fn())
        started.append("job_worker")

    if (not state.queue_reconciler_task) or state.queue_reconciler_task.done():
        state.queue_reconciler_task = asyncio.create_task(queue_reconciler_loop_fn())
        started.append("queue_reconciler")

    return started
