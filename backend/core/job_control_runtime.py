"""
Job/scan control runtime helpers extracted from ares_api.py.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from fastapi import HTTPException


@dataclass
class JobControlRuntimeDeps:
    state: Any
    canonical_job_kind: str
    autopilot_max_phase: int
    normalize_job_kind_fn: Callable[[Any], str]
    job_latest_active_scan_id_fn: Callable[[str, str], Awaitable[Optional[str]]]
    job_list_fn: Callable[[str, int], Awaitable[list]]
    job_get_fn: Callable[[str], Awaitable[Optional[dict]]]
    job_get_coverage_v1_fn: Callable[..., Awaitable[Any]]
    fallback_coverage_response_from_job_fn: Callable[..., Awaitable[Any]]
    job_update_fn: Callable[..., Awaitable[None]]
    job_now_fn: Callable[[], str]
    terminate_process_tree_fn: Callable[[Any], None]
    normalize_unified_scan_cfg_fn: Callable[[dict], dict]
    validate_omni_config_fn: Callable[[dict], str]
    validate_target_fn: Callable[[str, Any], bool]
    job_create_fn: Callable[..., Awaitable[None]]
    queue_enqueue_fn: Callable[..., Awaitable[None]]
    audit_log_fn: Callable[..., Awaitable[Any]]
    stop_metric_inc_fn: Callable[[str], None]
    cleanup_scan_runtime_fn: Callable[[str], None]


def get_scan_status_payload(*, current_user_sub: str, deps: JobControlRuntimeDeps) -> dict:
    running_scan_id = str(deps.state.running_job_by_user.get(current_user_sub) or "")
    running_kind = str(deps.state.running_kind_by_user.get(current_user_sub) or "")
    meta = dict(deps.state.omni_meta.get(current_user_sub, {}) or {})
    if running_scan_id:
        meta.setdefault("scan_id", running_scan_id)
        return {
            "running": True,
            "pid": (deps.state.proc.pid if (deps.state.proc and deps.state.proc.returncode is None) else None),
            "active_scan": deps.state.active_scans.get(current_user_sub),
            "active_job": running_scan_id,
            "kind": deps.normalize_job_kind_fn(running_kind),
            "meta": meta,
        }
    if deps.state.proc is not None and deps.state.proc.returncode is None:
        return {
            "running": True,
            "pid": deps.state.proc.pid,
            "active_scan": deps.state.active_scans.get(current_user_sub),
            "meta": meta,
        }
    return {"running": False, "meta": meta}


async def list_jobs_payload(*, current_user_sub: str, deps: JobControlRuntimeDeps) -> list:
    return await deps.job_list_fn(current_user_sub, limit=30)


async def get_job_payload(*, scan_id: str, current_user_sub: str, deps: JobControlRuntimeDeps) -> dict:
    job = await deps.job_get_fn(scan_id)
    if not job or job.get("user_id") != current_user_sub:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


async def get_job_coverage_payload(
    *,
    scan_id: str,
    current_user_sub: str,
    limit: int,
    cursor: int,
    deps: JobControlRuntimeDeps,
):
    job = await deps.job_get_fn(scan_id)
    if not job or job.get("user_id") != current_user_sub:
        raise HTTPException(status_code=404, detail="Job not found")

    coverage_response = await deps.job_get_coverage_v1_fn(scan_id=scan_id, limit=limit, cursor=cursor)
    if coverage_response is None:
        coverage_response = await deps.fallback_coverage_response_from_job_fn(job, scan_id, limit=limit, cursor=cursor)
    return coverage_response


async def stop_job_payload(*, scan_id: str, current_user_sub: str, deps: JobControlRuntimeDeps) -> dict:
    job = await deps.job_get_fn(scan_id)
    if not job or job.get("user_id") != current_user_sub:
        raise HTTPException(status_code=404, detail="Job not found")

    status_ = str(job.get("status") or "")
    kind = deps.normalize_job_kind_fn(job.get("kind"))

    if status_ == "queued":
        deps.state.cancelled_jobs.add(scan_id)
        await deps.job_update_fn(scan_id, status="stopped", finished_at=deps.job_now_fn(), error="stopped_by_user")
        return {"status": "stopped"}

    if status_ != "running":
        return {"status": status_}

    if kind == deps.canonical_job_kind:
        if str(deps.state.running_job_by_user.get(current_user_sub) or "") not in {"", scan_id}:
            raise HTTPException(status_code=400, detail="Job is not the active running scan for this user")
        # 1. Signal stop so scan functions can exit early at checkpoints
        if hasattr(deps.state, 'stop_requested_users'):
            deps.state.stop_requested_users.add(current_user_sub)
        # 2. Kill subprocess FIRST (immediate effect on sqlmap/native engines)
        if deps.state.proc and deps.state.proc.returncode is None:
            deps.terminate_process_tree_fn(deps.state.proc)
        # 3. Cancel the asyncio task AFTER subprocess is dead
        t = deps.state.current_job_task_by_user.get(current_user_sub)
        if t and not t.done():
            t.cancel()
        await deps.job_update_fn(scan_id, status="stopped", finished_at=deps.job_now_fn(), error="stopped_by_user")
        deps.cleanup_scan_runtime_fn(current_user_sub)
        # Clear stop flag after cleanup
        if hasattr(deps.state, 'stop_requested_users'):
            deps.state.stop_requested_users.discard(current_user_sub)
        return {"status": "stopped"}

    await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=f"unknown kind for stop: {kind}")
    return {"status": "failed"}


async def stop_scan_payload(*, current_user_sub: str, deps: JobControlRuntimeDeps) -> dict:
    running_scan_id = str(deps.state.running_job_by_user.get(current_user_sub) or "")
    running_kind = str(deps.state.running_kind_by_user.get(current_user_sub) or "")
    if running_scan_id:
        res = await stop_job_payload(scan_id=running_scan_id, current_user_sub=current_user_sub, deps=deps)
        deps.stop_metric_inc_fn(deps.normalize_job_kind_fn(running_kind))
        if current_user_sub in deps.state.omni_meta:
            deps.state.omni_meta[current_user_sub]["last_message"] = "stop_requested"
        await deps.audit_log_fn(
            user_id=current_user_sub,
            action="scan_unified_stopped",
            resource_type="scan",
            resource_id=running_scan_id,
            after={"kind": deps.normalize_job_kind_fn(running_kind)},
            status="success",
        )
        return res

    latest_scan_id = await deps.job_latest_active_scan_id_fn(str(current_user_sub), deps.canonical_job_kind)
    if latest_scan_id:
        res = await stop_job_payload(scan_id=str(latest_scan_id), current_user_sub=current_user_sub, deps=deps)
        deps.stop_metric_inc_fn(deps.canonical_job_kind)
        if current_user_sub in deps.state.omni_meta:
            deps.state.omni_meta[current_user_sub]["last_message"] = "stop_requested"
        await deps.audit_log_fn(
            user_id=current_user_sub,
            action="scan_unified_stopped",
            resource_type="scan",
            resource_id=str(latest_scan_id),
            status="success",
        )
        return res

    if not deps.state.proc or deps.state.proc.returncode is not None:
        raise HTTPException(status_code=400, detail="No scan running")

    deps.terminate_process_tree_fn(deps.state.proc)
    deps.stop_metric_inc_fn(deps.canonical_job_kind)
    scan_info = deps.state.active_scans.get(current_user_sub, {}) or {}
    scan_id = str(scan_info.get("scan_id") or "")
    if scan_id:
        await deps.job_update_fn(scan_id, status="stopped", finished_at=deps.job_now_fn(), error="stopped_by_user")
    deps.cleanup_scan_runtime_fn(current_user_sub)
    return {"status": "stopped"}


async def retry_job_payload(*, scan_id: str, current_user: Any, deps: JobControlRuntimeDeps) -> dict:
    job = await deps.job_get_fn(scan_id)
    if not job or job.get("user_id") != current_user.sub:
        raise HTTPException(status_code=404, detail="Job not found")

    status_ = str(job.get("status") or "")
    if status_ in ("queued", "running"):
        raise HTTPException(status_code=409, detail="Job is still active; stop it before retry")

    cfg = deps.normalize_unified_scan_cfg_fn(job.get("config") or {})
    kind = deps.normalize_job_kind_fn(job.get("kind"))
    target_url = str(job.get("target_url") or "")
    autopilot = bool(job.get("autopilot"))
    phase = int(job.get("phase") or 1)
    max_phase = int(job.get("max_phase") or deps.autopilot_max_phase)

    try:
        mode = deps.validate_omni_config_fn(cfg)
    except HTTPException as exc:
        raise HTTPException(status_code=exc.status_code, detail=f"Retry denied: {exc.detail}")
    if mode in ("web", "graphql") and not deps.validate_target_fn(str(cfg.get("url") or target_url), current_user):
        raise HTTPException(status_code=403, detail="Target blocked by policy (retry denied)")

    new_scan_id = secrets.token_urlsafe(12)
    await deps.job_create_fn(
        scan_id=new_scan_id,
        user_id=current_user.sub,
        kind=kind,
        status="queued",
        phase=phase,
        max_phase=max_phase,
        autopilot=autopilot,
        target_url=target_url or str(cfg.get("url") or ""),
        cfg=cfg,
        pid=None,
        priority=int(job.get("priority") or 0),
    )
    await deps.queue_enqueue_fn(new_scan_id, priority=int(job.get("priority") or 0))
    await deps.audit_log_fn(
        user_id=current_user.sub,
        action="job_retry_queued",
        resource_type="scan",
        resource_id=new_scan_id,
        after={"retry_of": scan_id, "kind": kind, "target_url": target_url},
        status="success",
    )
    return {"message": "Retry queued", "scan_id": new_scan_id, "status": "queued"}

