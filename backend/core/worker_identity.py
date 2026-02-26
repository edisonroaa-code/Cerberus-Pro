"""
Worker identity payload builder extracted from ares_api.py.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Set, Type


def build_worker_payload(
    *,
    user_id: str,
    users: Dict[str, Any],
    role_admin: Any,
    role_permissions: Dict[Any, Set[Any]],
    token_type_access: Any,
    jwt_payload_cls: Type[Any],
    access_token_expire_minutes: int,
) -> Any:
    user_obj = users.get(user_id)
    role = user_obj.role if user_obj else role_admin
    perms = list(role_permissions.get(role, set()))
    now = datetime.now(timezone.utc)
    return jwt_payload_cls(
        sub=str(user_id),
        username=(user_obj.username if user_obj else str(user_id)),
        email=(user_obj.email if user_obj else ""),
        role=role,
        permissions=perms,
        token_type=token_type_access,
        session_id="worker",
        iat=now,
        exp=now + timedelta(minutes=int(access_token_expire_minutes)),
        jti=f"worker_{secrets.token_urlsafe(8)}",
    )
