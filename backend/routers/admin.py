"""
Admin Router — Extracted from ares_api.py (Fase 5 Refactoring).
Handles: list_users, delete_user, create_api_key, list_api_keys.
"""

import os
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException, Depends, status

from auth_security import (
    Permission, get_current_user, require_permission,
    JWTPayload, APIKeyManager, APIKeyModel,
)

logger = logging.getLogger("cerberus.routers.admin")
router = APIRouter()


def _get_state():
    from ares_api import state
    return state


async def _audit(user_id, action, resource_type, resource_id=None, status_val="success"):
    from ares_api import audit_log
    await audit_log(
        user_id=user_id, action=action, resource_type=resource_type,
        resource_id=resource_id, status=status_val,
    )


# ============================================================================
# USER MANAGEMENT (ADMIN ONLY)
# ============================================================================

@router.get("/users")
async def list_users(
    current_user: JWTPayload = Depends(require_permission(Permission.USER_READ))
):
    """List all users (admin only)"""
    state = _get_state()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at,
            "last_login": u.last_login,
            "mfa_enabled": u.mfa_enabled
        }
        for u in state.users.values()
    ]


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: JWTPayload = Depends(require_permission(Permission.USER_DELETE))
):
    """Delete user (super admin only)"""
    state = _get_state()

    if user_id not in state.users:
        raise HTTPException(status_code=404, detail="User not found")

    user = state.users.pop(user_id)

    await _audit(
        user_id=current_user.sub, action="user_deleted",
        resource_type="user", resource_id=user_id,
    )

    logger.info(f"✅ User deleted: {user.username}")
    return {"message": "User deleted"}


# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

@router.post("/api-keys")
async def create_api_key(
    name: str,
    scopes: List[Permission] = [Permission.SCAN_READ],
    current_user: JWTPayload = Depends(get_current_user)
):
    """Create API key for user"""
    state = _get_state()

    api_key = APIKeyManager.generate_api_key()
    api_key_hash = APIKeyManager.hash_api_key(api_key)

    key_model = APIKeyModel(
        id=f"key_{os.urandom(4).hex()}",
        user_id=current_user.sub,
        key_hash=api_key_hash,
        name=name,
        scopes=scopes,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        last_used=None
    )

    if current_user.sub not in state.api_keys:
        state.api_keys[current_user.sub] = []

    state.api_keys[current_user.sub].append(key_model)

    logger.info(f"✅ API key created: {name} for {current_user.username}")

    return {"key": api_key, "key_id": key_model.id}


@router.get("/api-keys")
async def list_api_keys(current_user: JWTPayload = Depends(get_current_user)):
    """List user's API keys"""
    state = _get_state()

    keys = state.api_keys.get(current_user.sub, [])
    return [
        {
            "id": k.id,
            "name": k.name,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "created_at": k.created_at,
            "last_used": k.last_used
        }
        for k in keys
    ]
