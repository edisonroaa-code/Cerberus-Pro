"""
Dependency injection container for the Cerberus API.

This module eliminates circular imports by providing a centralized
AppDeps object that routers can access via FastAPI Depends() instead
of importing directly from ares_api.

Usage in routers:
    from backend.core.app_deps import get_app_deps, AppDeps

    @router.get("/example")
    async def example(deps: AppDeps = Depends(get_app_deps)):
        deps.state.users  # access state
        await deps.broadcast_log("COMP", "INFO", "message")
        await deps.audit_log(user_id="x", action="y", resource_type="z")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

from backend.core.runtime_state import CerberusState


@dataclass
class AppDeps:
    """
    Central dependency bag injected into routers via FastAPI Depends.

    This replaces the pattern of `from ares_api import state, broadcast_log, audit_log`
    which causes circular import chains.
    """
    state: CerberusState
    broadcast_log: Callable[..., Coroutine]
    audit_log: Callable[..., Coroutine]
    history_dir: str = ""
    safe_history_path_fn: Optional[Callable[[str], str]] = None
    normalize_job_kind_fn: Optional[Callable[[Any], str]] = None


# Module-level singleton, set once during app startup
_app_deps: Optional[AppDeps] = None


def configure_app_deps(deps: AppDeps) -> None:
    """Called once during FastAPI lifespan to wire up the deps."""
    global _app_deps
    _app_deps = deps


def get_app_deps() -> AppDeps:
    """FastAPI Depends() resolver. Returns the configured AppDeps singleton."""
    if _app_deps is None:
        raise RuntimeError(
            "AppDeps not configured. Call configure_app_deps() during app startup."
        )
    return _app_deps
