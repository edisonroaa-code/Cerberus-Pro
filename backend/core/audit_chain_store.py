"""
SQLite audit-chain persistence extracted from ares_api.py.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Dict


def init_audit_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
            """
        )
        conn.commit()


def append_audit_chain(db_path: str, log_entry: Any) -> None:
    payload = {
        "id": getattr(log_entry, "id", None),
        "timestamp": getattr(log_entry, "timestamp").isoformat(),
        "user_id": getattr(log_entry, "user_id", None),
        "action": getattr(log_entry, "action", None),
        "resource_type": getattr(log_entry, "resource_type", None),
        "resource_id": getattr(log_entry, "resource_id", None),
        "status": getattr(log_entry, "status", None),
        "before": getattr(log_entry, "before", None),
        "after": getattr(log_entry, "after", None),
        "error_message": getattr(log_entry, "error_message", None),
        "ip_address": getattr(log_entry, "ip_address", None),
        "user_agent": getattr(log_entry, "user_agent", None),
    }
    payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row[0] if row else "GENESIS"
        event_hash = hashlib.sha256((prev_hash + payload_json).encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT INTO audit_events
            (event_id, timestamp, user_id, action, resource_type, resource_id, status, payload_json, prev_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                getattr(log_entry, "id", None),
                getattr(log_entry, "timestamp").isoformat(),
                getattr(log_entry, "user_id", None),
                getattr(log_entry, "action", None),
                getattr(log_entry, "resource_type", None),
                getattr(log_entry, "resource_id", None),
                getattr(log_entry, "status", None),
                payload_json,
                prev_hash,
                event_hash,
            ),
        )
        conn.commit()


def verify_audit_chain(db_path: str) -> Dict[str, Any]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, payload_json, prev_hash, event_hash FROM audit_events ORDER BY id ASC"
        ).fetchall()
    prev = "GENESIS"
    for row in rows:
        row_id, payload_json, prev_hash, event_hash = row
        if prev_hash != prev:
            return {"ok": False, "reason": "prev_hash mismatch", "row_id": row_id}
        expected = hashlib.sha256((prev + payload_json).encode("utf-8")).hexdigest()
        if expected != event_hash:
            return {"ok": False, "reason": "event_hash mismatch", "row_id": row_id}
        prev = event_hash
    return {"ok": True, "events": len(rows)}
