"""
Audit runtime helpers extracted from ares_api.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AuditRuntimeDeps:
    state: Any
    logger: Any
    audit_log_cls: Any
    append_audit_chain_fn: Any
    verify_audit_chain_fn: Any


async def audit_log(
    *,
    user_id: str,
    action: str,
    resource_type: str,
    deps: AuditRuntimeDeps,
    resource_id: Optional[str] = None,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    status: str = "success",
    error_message: Optional[str] = None,
) -> None:
    """Create and append an audit log entry."""
    log_entry = deps.audit_log_cls(
        id=f"audit_{os.urandom(4).hex()}",
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        before=before,
        after=after,
        status=status,
        error_message=error_message,
        timestamp=datetime.now(timezone.utc),
        ip_address="127.0.0.1",
        user_agent="unknown",
    )

    deps.state.audit_logs.append(log_entry)
    deps.append_audit_chain_fn(log_entry)
    deps.logger.info("Audit: %s - %s by %s", action, resource_type, user_id)


def list_audit_logs(*, deps: AuditRuntimeDeps, limit: int = 100) -> List[Dict[str, Any]]:
    return [log.dict() for log in deps.state.audit_logs[-limit:]]


def verify_audit_chain(*, deps: AuditRuntimeDeps) -> dict:
    return deps.verify_audit_chain_fn()

