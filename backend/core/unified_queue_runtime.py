"""
Unified scan queue/start helpers extracted from ares_api.py.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status


@dataclass
class UnifiedQueueRuntimeDeps:
    canonical_job_kind: str
    autopilot_max_phase: int
    normalize_unified_scan_cfg_fn: Callable[[dict], dict]
    validate_omni_config_fn: Callable[[dict], str]
    read_unified_runtime_cfg_fn: Callable[[dict], dict]
    validate_target_fn: Callable[[str, Any], bool]
    validate_network_host_fn: Callable[[str], bool]
    pending_jobs_count_fn: Callable[[str], int]
    job_create_fn: Callable[..., None]
    queue_enqueue_fn: Callable[..., Awaitable[None]]
    ensure_job_background_tasks_fn: Callable[..., Awaitable[list]]
    scan_start_metric_inc_fn: Callable[[str], None]
    audit_log_fn: Callable[..., Awaitable[Any]]
    logger: Any


async def queue_unified_scan(
    request: Request,
    current_user: Any,
    *,
    source_endpoint: str,
    deps: UnifiedQueueRuntimeDeps,
) -> dict:
    body = await request.json()
    raw_cfg = body.get("config", {}) or {}
    if "unified" not in raw_cfg and "omni" in raw_cfg:
        raise HTTPException(status_code=400, detail="Hard break activo: usa config.unified (config.omni no soportado)")
    cfg = deps.normalize_unified_scan_cfg_fn(raw_cfg)
    target_url = str(cfg.get("url", "") or "")
    mode = deps.validate_omni_config_fn(cfg)
    unified_cfg = deps.read_unified_runtime_cfg_fn(cfg)

    if mode in ("web", "graphql") and not deps.validate_target_fn(target_url, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target not allowed or is private IP",
        )
    if mode == "direct_db":
        db_cfg = (unified_cfg.get("directDb", {}) or {})
        if not deps.validate_network_host_fn(str(db_cfg.get("host", ""))):
            raise HTTPException(status_code=403, detail="Direct DB host blocked by policy")
    if mode == "ws":
        ws_url = str(unified_cfg.get("wsUrl", ""))
        ws_host = urlparse(ws_url).hostname or ""
        if not ws_host or not deps.validate_network_host_fn(ws_host):
            raise HTTPException(status_code=403, detail="WebSocket host blocked by policy")
    if mode == "mqtt":
        mqtt_host = str((unified_cfg.get("mqtt", {}) or {}).get("host", ""))
        if not deps.validate_network_host_fn(mqtt_host):
            raise HTTPException(status_code=403, detail="MQTT host blocked by policy")
    if mode == "grpc":
        grpc_host = str((unified_cfg.get("grpc", {}) or {}).get("host", ""))
        if not deps.validate_network_host_fn(grpc_host):
            raise HTTPException(status_code=403, detail="gRPC host blocked by policy")

    max_pending = int(os.environ.get("MAX_PENDING_JOBS_PER_USER", "3"))
    if deps.pending_jobs_count_fn(current_user.sub) >= max_pending:
        raise HTTPException(status_code=409, detail=f"Too many pending jobs (limit={max_pending})")

    scan_id = secrets.token_urlsafe(12)
    deps.job_create_fn(
        scan_id=scan_id,
        user_id=current_user.sub,
        kind=deps.canonical_job_kind,
        status="queued",
        phase=int(cfg.get("autoPilotPhase") or 1),
        max_phase=deps.autopilot_max_phase,
        autopilot=bool(cfg.get("autoPilot")),
        target_url=target_url or mode,
        cfg=cfg,
        pid=None,
        priority=int(cfg.get("priority") or 0),
    )
    await deps.queue_enqueue_fn(scan_id, priority=int(cfg.get("priority") or 0))
    await deps.ensure_job_background_tasks_fn()
    deps.scan_start_metric_inc_fn(deps.canonical_job_kind)

    deps.logger.info(
        "Unified job queued by %s scan_id=%s mode=%s source=%s",
        current_user.username,
        scan_id,
        mode,
        source_endpoint,
    )
    await deps.audit_log_fn(
        user_id=current_user.sub,
        action="scan_unified_queued",
        resource_type="scan",
        resource_id=scan_id,
        after={
            "mode": mode,
            "url": target_url,
            "kind": deps.canonical_job_kind,
            "source_endpoint": source_endpoint,
            "config": cfg,
        },
        status="success",
    )

    return {
        "message": "Unified job queued",
        "mode": mode,
        "scan_id": scan_id,
        "status": "queued",
        "kind": "unified",
        "canonical_endpoint": "/scan/start",
        "source_endpoint": source_endpoint,
    }

