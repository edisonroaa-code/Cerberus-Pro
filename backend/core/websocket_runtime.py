"""
WebSocket runtime helpers extracted from ares_api.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect, status


@dataclass
class WebsocketRuntimeDeps:
    state: Any
    logger: Any
    jwt_manager: Any
    role_agent: Any
    ws_connections_metric: Any
    environment: str
    ws_handshake_debug: bool
    disable_local_dev_ws: bool


async def websocket_endpoint(websocket: WebSocket, deps: WebsocketRuntimeDeps) -> None:
    """Secure WebSocket for real-time log streaming."""
    token = websocket.query_params.get("token")
    if not token and "access_token" in websocket.cookies:
        token = websocket.cookies.get("access_token")

    client_host = websocket.client.host if websocket.client else ""
    origin = websocket.headers.get("origin", "")

    if deps.ws_handshake_debug:
        deps.logger.info(
            "WS handshake: host=%s origin=%s token=%s env=%s local_bypass_disabled=%s",
            client_host,
            origin,
            (token[:8] + "...") if token else "none",
            deps.environment,
            deps.disable_local_dev_ws,
        )

    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        user = deps.jwt_manager.verify_token(token)
        if user.jti in deps.state.revoked_tokens:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception as exc:
        deps.logger.warning(
            "WebSocket auth failed: %s (token=%s..., env=%s)",
            exc,
            token[:8] if token else "none",
            deps.environment,
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    deps.state.websocket_clients.add(websocket)
    deps.ws_connections_metric.set(len(deps.state.websocket_clients))

    deps.logger.info("WebSocket connected: %s", user.username)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        deps.state.websocket_clients.discard(websocket)
        deps.ws_connections_metric.set(len(deps.state.websocket_clients))
        deps.logger.info("WebSocket disconnected: %s", user.username)


async def broadcast(obj: dict, deps: WebsocketRuntimeDeps) -> None:
    """Broadcast message to all connected WebSocket clients."""
    disconnected = []

    for ws in deps.state.websocket_clients:
        try:
            await ws.send_json(obj)
        except Exception:
            disconnected.append(ws)

    for ws in disconnected:
        deps.state.websocket_clients.discard(ws)
    deps.ws_connections_metric.set(len(deps.state.websocket_clients))


async def websocket_agent_endpoint(websocket: WebSocket, deps: WebsocketRuntimeDeps) -> None:
    """Secure Agent Control Channel."""
    auth_header = websocket.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        user = deps.jwt_manager.verify_token(token)
        if user.role != deps.role_agent:
            deps.logger.warning("Agent WS denied using role: %s", user.role)
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception as exc:
        deps.logger.warning("Agent WS auth failed: %s", exc)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    deps.logger.info("Agent C2 connected: %s", user.username)

    deps.state.agent_connections[user.sub] = websocket

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "heartbeat":
                    await websocket.send_json({"type": "ack"})
                elif msg.get("type") == "result":
                    deps.logger.info("Result received from %s: %s", user.username, msg.get("taskId"))
            except Exception:
                pass
    except WebSocketDisconnect:
        deps.state.agent_connections.pop(user.sub, None)
        deps.logger.info("Agent disconnected: %s", user.username)
