"""
Standalone worker runner extracted from ares_api.py.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional


async def run_standalone_worker(
    *,
    state: Any,
    logger: Any,
    worker_id: str,
    job_queue_backend: str,
    stop_event: Optional[asyncio.Event],
    init_audit_db_fn: Callable[[], None],
    init_jobs_db_fn: Callable[[], None],
    init_job_queue_backend_fn: Callable[[], Awaitable[None]],
    jobs_recover_on_startup_fn: Callable[[], None],
    enqueue_queued_jobs_fn: Callable[[], Awaitable[None]],
    ensure_job_background_tasks_fn: Callable[[bool], Awaitable[list]],
) -> None:
    logger.info("🧾 Cerberus standalone worker starting worker_id=%s", worker_id)
    init_audit_db_fn()
    init_jobs_db_fn()
    await init_job_queue_backend_fn()

    if (job_queue_backend != "redis") and (state.redis is None):
        logger.warning(
            "Standalone worker running with memory backend. "
            "Use JOB_QUEUE_BACKEND=redis for multi-process queue sharing."
        )

    jobs_recover_on_startup_fn()
    await enqueue_queued_jobs_fn()
    await ensure_job_background_tasks_fn(True)

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            await asyncio.sleep(1)
    finally:
        if state.job_worker_task and not state.job_worker_task.done():
            state.job_worker_task.cancel()
        if state.queue_reconciler_task and not state.queue_reconciler_task.done():
            state.queue_reconciler_task.cancel()
        if state.redis is not None:
            try:
                await state.redis.aclose()
            except Exception:
                pass
        logger.info("🧾 Cerberus standalone worker stopped worker_id=%s", worker_id)
