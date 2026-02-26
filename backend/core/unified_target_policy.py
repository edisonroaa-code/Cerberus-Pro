"""
Unified target policy validation extracted from ares_api.py.
"""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlparse

from fastapi import HTTPException


def validate_unified_target_policy(
    *,
    mode: str,
    cfg: dict,
    user_id: str,
    payload_for_user_id_fn: Callable[[str], Any],
    read_unified_runtime_cfg_fn: Callable[[dict], dict],
    policy_engine: Any,
    action_type_scan: Any,
    validate_target_fn: Callable[[str, Any], bool],
    validate_network_host_fn: Callable[[str], bool],
) -> None:
    payload = payload_for_user_id_fn(user_id)
    target_url = str(cfg.get("url", "") or "")
    unified_cfg = read_unified_runtime_cfg_fn(cfg)

    policy_target = target_url or mode or "unknown"
    if mode == "direct_db":
        policy_target = str((unified_cfg.get("directDb", {}) or {}).get("host", "") or "direct_db")
    elif mode == "ws":
        ws_url = str(unified_cfg.get("wsUrl", ""))
        policy_target = (urlparse(ws_url).hostname or "").strip() or "ws"
    elif mode == "mqtt":
        policy_target = str((unified_cfg.get("mqtt", {}) or {}).get("host", "") or "mqtt")
    elif mode == "grpc":
        policy_target = str((unified_cfg.get("grpc", {}) or {}).get("host", "") or "grpc")

    if not policy_engine.check_authorization(action_type_scan, policy_target):
        raise HTTPException(status_code=403, detail="Target blocked by governance policy")

    if mode in ("web", "graphql"):
        if not validate_target_fn(target_url, payload):
            raise HTTPException(status_code=403, detail="target blocked by policy")
        return

    if mode == "direct_db":
        db_cfg = unified_cfg.get("directDb", {}) or {}
        if not validate_network_host_fn(str(db_cfg.get("host", ""))):
            raise HTTPException(status_code=403, detail="Direct DB host blocked by policy")
        return

    if mode == "ws":
        ws_url = str(unified_cfg.get("wsUrl", ""))
        ws_host = urlparse(ws_url).hostname or ""
        if not ws_host or not validate_network_host_fn(ws_host):
            raise HTTPException(status_code=403, detail="WebSocket host blocked by policy")
        return

    if mode == "mqtt":
        mqtt_host = str((unified_cfg.get("mqtt", {}) or {}).get("host", ""))
        if not validate_network_host_fn(mqtt_host):
            raise HTTPException(status_code=403, detail="MQTT host blocked by policy")
        return

    if mode == "grpc":
        grpc_host = str((unified_cfg.get("grpc", {}) or {}).get("host", ""))
        if not validate_network_host_fn(grpc_host):
            raise HTTPException(status_code=403, detail="gRPC host blocked by policy")
        return
