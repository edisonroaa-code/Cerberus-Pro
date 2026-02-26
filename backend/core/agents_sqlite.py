"""
SQLite persistence layer for C2 Agents.

Provides CRUD operations so agent data survives backend restarts.
Uses the same DB file pattern as jobs_sqlite.py for consistency.
"""

from __future__ import annotations

import json
import os
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("cerberus.core.agents_sqlite")

_DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db")
_DB_FILENAME = "agents.db"


def _get_db_path() -> str:
    db_dir = os.environ.get("CERBERUS_DB_DIR", _DEFAULT_DB_DIR)
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, _DB_FILENAME)


def _connect(db_path: Optional[str] = None) -> sqlite3.Connection:
    path = db_path or _get_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_agents_db(db_path: Optional[str] = None) -> None:
    """Create the agents and c2_tasks tables if they don't exist."""
    conn = _connect(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                client_id       TEXT UNIQUE NOT NULL,
                client_secret_hash TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                last_connected  TEXT,
                ip_address      TEXT,
                version         TEXT DEFAULT '1.0.0',
                is_active       INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS c2_tasks (
                id              TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                type            TEXT NOT NULL,
                data_json       TEXT DEFAULT '{}',
                priority        INTEGER DEFAULT 5,
                status          TEXT DEFAULT 'pending',
                result_json     TEXT,
                created_at      TEXT NOT NULL,
                completed_at    TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            );

            CREATE INDEX IF NOT EXISTS idx_agents_client_id ON agents(client_id);
            CREATE INDEX IF NOT EXISTS idx_c2_tasks_agent_status ON c2_tasks(agent_id, status);
        """)
        conn.commit()
        logger.info("Agents/C2Tasks SQLite schema ready")
    finally:
        conn.close()


# ============================================================================
# AGENT CRUD
# ============================================================================

def create_agent(
    *,
    agent_id: str,
    name: str,
    client_id: str,
    client_secret_hash: str,
    db_path: Optional[str] = None,
) -> Dict:
    """Insert a new agent row."""
    now = datetime.now(timezone.utc).isoformat()
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO agents (id, name, client_id, client_secret_hash, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (agent_id, name, client_id, client_secret_hash, now),
        )
        conn.commit()
        return get_agent(client_id=client_id, db_path=db_path) or {}
    finally:
        conn.close()


def get_agent(
    *,
    client_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Optional[Dict]:
    """Fetch a single agent by client_id or agent_id."""
    conn = _connect(db_path)
    try:
        if client_id:
            row = conn.execute("SELECT * FROM agents WHERE client_id = ?", (client_id,)).fetchone()
        elif agent_id:
            row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        else:
            return None
        return dict(row) if row else None
    finally:
        conn.close()


def list_agents(*, db_path: Optional[str] = None) -> List[Dict]:
    """List all agents."""
    conn = _connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_agent(
    *,
    client_id: str,
    db_path: Optional[str] = None,
    **fields,
) -> None:
    """Update arbitrary fields on an agent row."""
    if not fields:
        return
    allowed = {"name", "last_connected", "ip_address", "version", "is_active"}
    safe_fields = {k: v for k, v in fields.items() if k in allowed}
    if not safe_fields:
        return
    set_clause = ", ".join(f"{k} = ?" for k in safe_fields)
    values = list(safe_fields.values()) + [client_id]
    conn = _connect(db_path)
    try:
        conn.execute(f"UPDATE agents SET {set_clause} WHERE client_id = ?", values)
        conn.commit()
    finally:
        conn.close()


def deactivate_agent(*, client_id: str, db_path: Optional[str] = None) -> None:
    """Soft-delete an agent by marking is_active = 0."""
    update_agent(client_id=client_id, is_active=0, db_path=db_path)


# ============================================================================
# C2 TASK CRUD
# ============================================================================

def create_task(
    *,
    task_id: str,
    agent_id: str,
    task_type: str,
    task_data: Optional[Dict] = None,
    priority: int = 5,
    db_path: Optional[str] = None,
) -> Dict:
    """Insert a new C2 task."""
    now = datetime.now(timezone.utc).isoformat()
    data_json = json.dumps(task_data or {})
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO c2_tasks (id, agent_id, type, data_json, priority, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            (task_id, agent_id, task_type, data_json, priority, now),
        )
        conn.commit()
        return {"task_id": task_id, "status": "pending"}
    finally:
        conn.close()


def get_pending_tasks(
    *,
    agent_id: str,
    limit: int = 10,
    db_path: Optional[str] = None,
) -> List[Dict]:
    """Fetch pending tasks for a given agent, ordered by priority (descending)."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM c2_tasks
               WHERE agent_id = ? AND status = 'pending'
               ORDER BY priority DESC, created_at ASC
               LIMIT ?""",
            (agent_id, limit),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["data"] = json.loads(d.pop("data_json", "{}"))
            results.append(d)
        return results
    finally:
        conn.close()


def update_task_result(
    *,
    task_id: str,
    result: Optional[any] = None,
    success: bool = False,
    db_path: Optional[str] = None,
) -> None:
    """Mark a task as completed with its result."""
    now = datetime.now(timezone.utc).isoformat()
    status = "completed" if success else "failed"
    result_json = json.dumps(result) if result is not None else None
    conn = _connect(db_path)
    try:
        conn.execute(
            """UPDATE c2_tasks SET status = ?, result_json = ?, completed_at = ?
               WHERE id = ?""",
            (status, result_json, now, task_id),
        )
        conn.commit()
    finally:
        conn.close()
