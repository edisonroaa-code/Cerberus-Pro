"""
Worker-loop helpers extracted from ares_api.py.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional


async def job_heartbeat_loop(
    scan_id: str,
    *,
    heartbeat_seconds: int,
    worker_id: str,
    job_get: Callable[[str], Optional[dict]],
    job_update: Callable[..., None],
    job_now: Callable[[], str],
) -> None:
    while True:
        await asyncio.sleep(max(3, int(heartbeat_seconds)))
        job = await job_get(scan_id) or {}
        if str(job.get("status") or "") != "running":
            return
        await job_update(scan_id, heartbeat_at=job_now(), worker_id=worker_id)


async def job_worker_loop(
    *,
    state: Any,
    queue_pop_fn: Callable[[int], Awaitable[Optional[str]]],
    job_get: Callable[[str], Optional[dict]],
    normalize_job_kind: Callable[[Any], str],
    job_update: Callable[..., None],
    job_now: Callable[[], str],
    worker_id: str,
    run_job_by_kind_fn: Callable[[str, str, str, dict], Awaitable[None]],
    heartbeat_loop_fn: Callable[[str], Awaitable[None]],
) -> None:
    while not getattr(state, "kill_switch_active", False):
        scan_id = await queue_pop_fn(2)
        if not scan_id:
            continue
        try:
            if scan_id in state.cancelled_jobs:
                state.cancelled_jobs.discard(scan_id)
                continue

            job = await job_get(scan_id)
            if not job:
                continue
            if str(job.get("status")) != "queued":
                continue

            user_id = str(job.get("user_id") or "")
            kind = normalize_job_kind(job.get("kind"))
            cfg = job.get("config") or {}

            attempts = int(job.get("attempts") or 0) + 1
            now_iso = job_now()
            await job_update(
                scan_id,
                status="running",
                started_at=now_iso,
                error=None,
                worker_id=worker_id,
                heartbeat_at=now_iso,
                attempts=attempts,
            )
            state.running_job_by_user[user_id] = scan_id
            state.running_kind_by_user[user_id] = kind

            hb_task = asyncio.create_task(heartbeat_loop_fn(scan_id))

            # Worker-owned task (so /jobs/{id}/stop can cancel it).
            task = asyncio.create_task(run_job_by_kind_fn(scan_id, user_id, kind, cfg))
            state.current_job_task_by_user[user_id] = task
            try:
                await task
            finally:
                if hb_task and not hb_task.done():
                    hb_task.cancel()
                state.current_job_task_by_user.pop(user_id, None)
                state.running_job_by_user.pop(user_id, None)
                state.running_kind_by_user.pop(user_id, None)
        except Exception as exc:
            try:
                await job_update(scan_id, status="failed", finished_at=job_now(), error=str(exc))
            except Exception:
                pass
        finally:
            if state.redis is None:
                try:
                    state.job_queue.task_done()
                except Exception:
                    pass
