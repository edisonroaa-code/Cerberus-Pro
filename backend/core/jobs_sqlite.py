"""
SQLite job-store helpers extracted from ares_api.py.

These functions intentionally avoid framework dependencies so the API layer
can decide normalization/policy concerns while keeping SQL statements isolated.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence


def init_jobs_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_jobs (
                scan_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                phase INTEGER NOT NULL,
                max_phase INTEGER NOT NULL,
                autopilot INTEGER NOT NULL,
                target_url TEXT NOT NULL,
                config_json TEXT NOT NULL,
                pid INTEGER,
                worker_id TEXT,
                heartbeat_at TEXT,
                attempts INTEGER,
                priority INTEGER,
                result_filename TEXT,
                vulnerable INTEGER,
                error TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_created ON scan_jobs(user_id, created_at DESC)"
        )
        conn.commit()

    # Backward-compatible schema upgrades for existing DBs (best effort).
    with sqlite3.connect(db_path) as conn:
        for col_sql in (
            "ALTER TABLE scan_jobs ADD COLUMN worker_id TEXT",
            "ALTER TABLE scan_jobs ADD COLUMN heartbeat_at TEXT",
            "ALTER TABLE scan_jobs ADD COLUMN attempts INTEGER",
            "ALTER TABLE scan_jobs ADD COLUMN priority INTEGER",
        ):
            try:
                conn.execute(col_sql)
            except Exception:
                pass
        conn.commit()


def count_jobs(
    db_path: str, *, user_id: Optional[str] = None, statuses: Optional[Sequence[str]] = None
) -> int:
    where_parts: List[str] = []
    params: List[Any] = []
    if user_id is not None:
        where_parts.append("user_id = ?")
        params.append(str(user_id))
    if statuses:
        placeholders = ",".join(["?"] * len(statuses))
        where_parts.append(f"status IN ({placeholders})")
        params.extend([str(status) for status in statuses])
    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(f"SELECT COUNT(1) FROM scan_jobs{where_sql}", tuple(params)).fetchone()
    return int(row[0] if row else 0)


def latest_active_scan_id(db_path: str, *, user_id: str, kinds: Sequence[str]) -> Optional[str]:
    if not kinds:
        return None
    placeholders = ",".join(["?"] * len(kinds))
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            f"SELECT scan_id FROM scan_jobs WHERE user_id = ? AND kind IN ({placeholders}) AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1",
            (str(user_id), *[str(kind) for kind in kinds]),
        ).fetchone()
    return str(row[0]) if row and row[0] else None


def recover_running_jobs_on_startup(
    db_path: str, *, stale_seconds: int, now_iso: Optional[str] = None
) -> None:
    now = str(now_iso or datetime.now(timezone.utc).isoformat())
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT scan_id, heartbeat_at FROM scan_jobs WHERE status = ?",
            ("running",),
        ).fetchall()
        for scan_id, heartbeat_at in rows:
            stale = True
            try:
                if heartbeat_at:
                    hb = datetime.fromisoformat(str(heartbeat_at))
                    if hb.tzinfo is None:
                        hb = hb.replace(tzinfo=timezone.utc)
                    stale = (datetime.now(timezone.utc) - hb).total_seconds() >= int(stale_seconds)
            except Exception:
                stale = True
            reason = "backend_restarted_stale" if stale else "backend_restarted"
            conn.execute(
                "UPDATE scan_jobs SET status=?, finished_at=?, error=? WHERE scan_id=?",
                ("interrupted", now, reason, str(scan_id)),
            )
        conn.commit()


def list_queued_job_ids(db_path: str) -> List[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT scan_id FROM scan_jobs
            WHERE status = ?
            ORDER BY created_at ASC
            """,
            ("queued",),
        ).fetchall()
    return [str(scan_id) for (scan_id,) in rows]


def create_job(
    db_path: str,
    *,
    scan_id: str,
    user_id: str,
    kind: str,
    status: str,
    phase: int,
    max_phase: int,
    autopilot: bool,
    target_url: str,
    cfg: Dict[str, Any],
    created_at: str,
    started_at: Optional[str] = None,
    pid: Optional[int] = None,
    priority: int = 0,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_jobs
            (scan_id, user_id, kind, status, created_at, started_at, phase, max_phase, autopilot, target_url, config_json, pid, worker_id, heartbeat_at, attempts, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(scan_id),
                str(user_id),
                str(kind),
                str(status),
                str(created_at),
                (str(started_at) if started_at else None),
                int(phase),
                int(max_phase),
                1 if bool(autopilot) else 0,
                str(target_url),
                json.dumps(cfg or {}, ensure_ascii=False, sort_keys=True),
                int(pid) if pid is not None else None,
                None,
                None,
                0,
                int(priority),
            ),
        )
        conn.commit()


def update_job(db_path: str, *, scan_id: str, updates: Dict[str, Any]) -> None:
    if not updates:
        return
    cols = ", ".join([f"{key}=?" for key in updates.keys()])
    values = list(updates.values())
    with sqlite3.connect(db_path) as conn:
        conn.execute(f"UPDATE scan_jobs SET {cols} WHERE scan_id = ?", (*values, str(scan_id)))
        conn.commit()


def get_job(db_path: str, *, scan_id: str) -> Optional[dict]:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT scan_id,user_id,kind,status,created_at,started_at,finished_at,phase,max_phase,autopilot,target_url,config_json,pid,worker_id,heartbeat_at,attempts,priority,result_filename,vulnerable,error
            FROM scan_jobs WHERE scan_id = ?
            """,
            (str(scan_id),),
        ).fetchone()
    if not row:
        return None
    keys = [
        "scan_id",
        "user_id",
        "kind",
        "status",
        "created_at",
        "started_at",
        "finished_at",
        "phase",
        "max_phase",
        "autopilot",
        "target_url",
        "config_json",
        "pid",
        "worker_id",
        "heartbeat_at",
        "attempts",
        "priority",
        "result_filename",
        "vulnerable",
        "error",
    ]
    out = dict(zip(keys, row))
    try:
        out["config"] = json.loads(out.pop("config_json") or "{}")
    except Exception:
        out["config"] = {}
        out.pop("config_json", None)
    out["autopilot"] = bool(out.get("autopilot"))
    if out.get("vulnerable") is not None:
        out["vulnerable"] = bool(out["vulnerable"])
    return out


def list_jobs(db_path: str, *, user_id: str, limit: int = 30) -> List[dict]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT scan_id,kind,status,created_at,started_at,finished_at,phase,max_phase,autopilot,target_url,pid,worker_id,heartbeat_at,attempts,priority,result_filename,vulnerable,error
            FROM scan_jobs WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (str(user_id), int(limit)),
        ).fetchall()
    keys = [
        "scan_id",
        "kind",
        "status",
        "created_at",
        "started_at",
        "finished_at",
        "phase",
        "max_phase",
        "autopilot",
        "target_url",
        "pid",
        "worker_id",
        "heartbeat_at",
        "attempts",
        "priority",
        "result_filename",
        "vulnerable",
        "error",
    ]
    out: List[dict] = []
    for row in rows:
        item = dict(zip(keys, row))
        item["autopilot"] = bool(item.get("autopilot"))
        if item.get("vulnerable") is not None:
            item["vulnerable"] = bool(item["vulnerable"])
        out.append(item)
    return out
