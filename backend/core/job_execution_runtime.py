"""
Classic/omni job execution helpers extracted from ares_api.py.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional


@dataclass
class JobExecutionRuntimeDeps:
    state: Any
    logger: Any
    apply_autopilot_policy_fn: Callable[[dict, str, int], dict]
    job_get_fn: Callable[[str], Awaitable[Optional[dict]]]
    job_update_fn: Callable[..., Awaitable[None]]
    job_now_fn: Callable[[], str]
    queue_enqueue_fn: Callable[..., Awaitable[None]]
    validate_target_fn: Callable[[str, Any], bool]
    payload_for_user_id_fn: Callable[[str], Any]
    sqlmap_path: str
    sqlmap_non_interactive_flags_fn: Callable[[], List[str]]
    header_scrubber_cls: Any
    start_sqlmap_process_fn: Callable[[List[str]], Any]
    autopilot_max_phase: int
    scan_timeout_total_seconds: int
    terminate_process_tree_fn: Callable[[Any], None]
    broadcast_fn: Callable[[Dict[str, Any]], Awaitable[None]]
    scan_reader_task_fn: Callable[[str], Awaitable[None]]
    run_omni_surface_scan_fn: Callable[[str, dict], Awaitable[dict]]


async def scan_timeout_watchdog(user_id: str, timeout_seconds: int, deps: JobExecutionRuntimeDeps) -> None:
    await asyncio.sleep(timeout_seconds)
    if deps.state.proc and deps.state.proc.poll() is None:
        deps.terminate_process_tree_fn(deps.state.proc)
        await deps.broadcast_fn(
            {
                "type": "log",
                "component": "SISTEMA",
                "level": "ERROR",
                "msg": f"Scan detenido por timeout global ({timeout_seconds}s)",
            }
        )


async def run_classic_job(scan_id: str, user_id: str, cfg: dict, deps: JobExecutionRuntimeDeps) -> None:
    if deps.state.proc and deps.state.proc.poll() is None:
        job = await deps.job_get_fn(scan_id)
        job = job or {}
        attempts = int(job.get("attempts") or 0)
        if attempts >= 3:
            await deps.job_update_fn(
                scan_id,
                status="failed",
                finished_at=deps.job_now_fn(),
                error="engine_busy_too_many_attempts",
            )
            return
        await deps.job_update_fn(
            scan_id,
            status="queued",
            started_at=None,
            pid=None,
            error="requeued_due_to_active_proc",
        )
        await deps.queue_enqueue_fn(scan_id, priority=int(job.get("priority") or 0))
        return

    auto_pilot = bool(cfg.get("autoPilot", False))
    if auto_pilot:
        cfg = deps.apply_autopilot_policy_fn(cfg, mode="classic", phase=int(cfg.get("autoPilotPhase") or 1))
        await deps.job_update_fn(scan_id, config_json=json.dumps(cfg, ensure_ascii=False, sort_keys=True))

    target_url = str(cfg.get("url", "") or "")
    if not deps.validate_target_fn(target_url, deps.payload_for_user_id_fn(user_id)):
        await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error="target blocked by policy")
        return

    sql_config = cfg.get("sqlMap", {}) or {}
    cmd = [sys.executable, deps.sqlmap_path, "-u", target_url]
    cmd.extend(deps.sqlmap_non_interactive_flags_fn())
    if auto_pilot:
        cmd.append("--smart")
        cmd.append("--forms")

    if sql_config.get("threads"):
        cmd.append(f"--threads={int(sql_config['threads'])}")
    if sql_config.get("level"):
        cmd.append(f"--level={int(sql_config['level'])}")
    if sql_config.get("risk"):
        cmd.append(f"--risk={int(sql_config['risk'])}")
    if sql_config.get("technique"):
        cmd.append(f"--technique={sql_config['technique']}")
    if sql_config.get("tamper"):
        cmd.append(f"--tamper={sql_config['tamper']}")
    if sql_config.get("timeout"):
        cmd.append(f"--timeout={int(sql_config['timeout'])}")

    cmd.extend(deps.header_scrubber_cls.get_sqlmap_arguments())

    profile = cfg.get("profile")
    delay = float(sql_config.get("auto_delay", 0))
    if not auto_pilot:
        if profile == "Corporativo-Sigiloso":
            delay = 3
        elif profile == "Móvil-5G":
            delay = 1
        elif profile == "Crawler-Legítimo":
            delay = 0.5
        elif profile == "Ráfaga-Agresiva":
            delay = 0
    if delay > 0:
        cmd.append(f"--delay={delay}")

    if sql_config.get("hpp"):
        cmd.append("--hpp")
    if sql_config.get("hex"):
        cmd.append("--hex")
    if sql_config.get("currentUser"):
        cmd.append("--current-user")
    if sql_config.get("currentDb"):
        cmd.append("--current-db")
    if sql_config.get("getDbs"):
        cmd.append("--dbs")
    if sql_config.get("getTables"):
        cmd.append("--tables")
    if sql_config.get("dumpAll"):
        cmd.append("--dump")

    try:
        deps.state.proc = deps.start_sqlmap_process_fn(cmd)
    except Exception as exc:
        await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=f"spawn failed: {exc}")
        return

    deps.state.active_scans[user_id] = {
        "scan_id": scan_id,
        "url": target_url,
        "started": datetime.now(timezone.utc),
        "pid": deps.state.proc.pid,
        "phase": int(cfg.get("autoPilotPhase") or 1),
        "max_phase": deps.autopilot_max_phase,
        "autoPilot": auto_pilot,
        "config": cfg,
    }
    await deps.job_update_fn(
        scan_id,
        pid=int(deps.state.proc.pid),
        started_at=deps.job_now_fn(),
        status="running",
        phase=int(cfg.get("autoPilotPhase") or 1),
        max_phase=deps.autopilot_max_phase,
    )

    existing_watchdog = deps.state.scan_watchdogs.pop(user_id, None)
    if existing_watchdog and not existing_watchdog.done():
        existing_watchdog.cancel()
    deps.state.scan_watchdogs[user_id] = asyncio.create_task(
        scan_timeout_watchdog(user_id, deps.scan_timeout_total_seconds, deps)
    )

    await deps.scan_reader_task_fn(user_id)


async def run_omni_job(scan_id: str, user_id: str, cfg: dict, deps: JobExecutionRuntimeDeps) -> None:
    if cfg.get("autoPilot"):
        cfg = deps.apply_autopilot_policy_fn(
            cfg,
            mode=(cfg.get("mode") or "web").lower(),
            phase=int(cfg.get("autoPilotPhase") or 1),
        )
        await deps.job_update_fn(scan_id, config_json=json.dumps(cfg, ensure_ascii=False, sort_keys=True))

    deps.state.omni_meta[user_id] = dict(deps.state.omni_meta.get(user_id) or {})
    deps.state.omni_meta[user_id]["scan_id"] = scan_id
    try:
        await deps.run_omni_surface_scan_fn(user_id, cfg)
        job = await deps.job_get_fn(scan_id)
        job = job or {}
        if job.get("status") == "running":
            await deps.job_update_fn(scan_id, status="completed", finished_at=deps.job_now_fn())
    except asyncio.CancelledError:
        await deps.job_update_fn(scan_id, status="stopped", finished_at=deps.job_now_fn(), error="stopped_by_user")
        raise
    except Exception as exc:
        await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=str(exc))
    finally:
        deps.state.omni_meta.pop(user_id, None)
