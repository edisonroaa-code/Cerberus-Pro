"""
Runtime state container for the Cerberus API process.

This module exists to keep the monolithic API file focused on routing/orchestration
instead of state-structure definitions.
"""

from __future__ import annotations

import asyncio
import os
from typing import List, Optional

from auth_security import AuditLog


class CerberusState:
    """Central mutable state for a single backend process."""

    def __init__(self) -> None:
        self.proc = None
        self.websocket_clients: set = set()
        self.active_scans: dict = {}  # user_id -> scan_info
        self.audit_logs: List[AuditLog] = []
        self.revoked_tokens: set = set()  # JTI set
        self.users: dict = {}  # user_id -> User (in-memory; use DB in production)
        self.api_keys: dict = {}  # user_id -> [APIKeyModel]
        self.agents: dict = {}  # agent_id -> Agent
        self.agent_connections: dict = {}  # agent_id -> WebSocket
        self.omni_meta: dict = {}  # user_id -> runtime metadata
        self.scan_watchdogs: dict = {}  # user_id -> asyncio.Task

        # Job execution model (2026): enqueue -> worker -> running/completed.
        # This prevents request handlers from owning long-running processes.
        self.job_queue: "asyncio.Queue[str]" = asyncio.Queue(
            maxsize=int(os.environ.get("JOB_QUEUE_MAXSIZE", "200"))
        )
        self.job_worker_task: Optional[asyncio.Task] = None
        self.running_job_by_user: dict = {}  # user_id -> scan_id
        self.running_kind_by_user: dict = {}  # user_id -> kind ("unified")
        self.current_job_task_by_user: dict = {}  # user_id -> asyncio.Task (worker-owned)
        self.cancelled_jobs: set = set()  # scan_id cancelled before execution

        # Enterprise multi-instance queue support
        self.redis = None  # redis_async.Redis | None
        self.queue_reconciler_task: Optional[asyncio.Task] = None
        self.kill_switch_active: bool = False

