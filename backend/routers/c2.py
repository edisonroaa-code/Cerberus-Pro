"""
C2 / Agent Management Router — Extracted from ares_api.py (Fase 5 Refactoring).
Handles: create_agent, agent_login, stop_agent, c2_register, c2_beacon, c2_task_result,
         list_agents, submit_task, kill_agent.
"""

import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Dict

from backend.core.api_contracts import (
    AgentCreateRequest, AgentCreateResponse, AgentInfoPayload,
    AgentListResponse, CommandSentResponse, StatusResponse,
    TaskSubmitRequest, TaskSubmitResponse, TaskResultPayload,
)

from fastapi import APIRouter, Request, HTTPException, Depends

from auth_security import (
    JWTManager, TokenResponse, Role, Permission,
    SecurityConfig, get_current_user, require_permission,
    JWTPayload, TokenType, Agent, AgentCredentials,
)

logger = logging.getLogger("cerberus.routers.c2")
router = APIRouter()


def _get_state():
    from ares_api import state
    return state


async def _audit(user_id, action, resource_type, resource_id=None, status_val="success"):
    from ares_api import audit_log
    await audit_log(user_id=user_id, action=action, resource_type=resource_type,
                    resource_id=resource_id, status=status_val)


def _get_c2_server():
    from ares_api import C2Server
    # We import the module-level c2_server instance
    import ares_api
    if not hasattr(ares_api, '_c2_server_instance'):
        ares_api._c2_server_instance = C2Server()
    return ares_api._c2_server_instance


async def _broadcast_log(component, level, msg, metadata=None):
    from ares_api import broadcast_log
    await broadcast_log(component, level, msg, metadata)


# ============================================================================
# AGENT MANAGEMENT
# ============================================================================

@router.post("/agents/create", response_model=AgentCreateResponse)
async def create_agent(
    body: AgentCreateRequest,
    current_user: JWTPayload = Depends(get_current_user)
):
    """Create a new C2 Agent (Admin/Lead only)"""
    state = _get_state()

    if current_user.role not in [Role.ADMIN, Role.SUPER_ADMIN, Role.LEAD]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    agent_name = body.agent_name
    client_id = f"ag_{secrets.token_urlsafe(8)}"
    client_secret = secrets.token_urlsafe(32)
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()

    agent = Agent(
        id=f"agent_{secrets.token_urlsafe(8)}",
        name=agent_name,
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        created_at=datetime.now(timezone.utc),
        last_connected=None,
        ip_address=None,
        version="1.0.0"
    )

    state.agents[client_id] = agent
    logger.info(f"🤖 Agent created: {agent.name} (ID: {client_id}) by {current_user.username}")

    return AgentCreateResponse(
        agent_id=agent.id, name=agent.name,
        client_id=client_id, client_secret=client_secret
    )


@router.post("/agents/login", response_model=TokenResponse)
async def agent_login(credentials: AgentCredentials, request: Request):
    """Authenticate C2 Agent"""
    state = _get_state()

    agent = state.agents.get(credentials.client_id)
    if not agent:
        hmac.compare_digest("a", "b")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    input_hash = hashlib.sha256(credentials.client_secret.encode()).hexdigest()
    if not hmac.compare_digest(input_hash, agent.client_secret_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not agent.is_active:
        raise HTTPException(status_code=403, detail="Agent disabled")

    access_token = JWTManager.create_token(
        user_id=agent.id, username=agent.name,
        email=f"{agent.client_id}@agents.cerberus.local",
        role=Role.AGENT, token_type=TokenType.ACCESS
    )

    agent.last_connected = datetime.now(timezone.utc)
    agent.ip_address = request.client.host

    logger.info(f"🤖 Agent authenticated: {agent.name} from {request.client.host}")

    return TokenResponse(
        access_token=access_token,
        refresh_token="agent_no_refresh",
        expires_in=SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/agents/{agent_id}/stop", response_model=CommandSentResponse)
async def stop_agent(
    agent_id: str,
    current_user: JWTPayload = Depends(require_permission(Permission.AGENT_MANAGE))
):
    """Remote Stop Action for C2 Agent"""
    state = _get_state()

    target_ws = state.agent_connections.get(agent_id)
    if not target_ws:
        raise HTTPException(status_code=404, detail="Agent not connected or not found")

    try:
        cmd_id = secrets.token_hex(4)
        await target_ws.send_json({"type": "command", "cmd": "stop", "id": cmd_id})

        logger.info(f"🛑 Stop command sent to agent {agent_id} by {current_user.username}")

        await _audit(user_id=current_user.sub, action="agent_stop",
                     resource_type="agent", resource_id=agent_id)

        return CommandSentResponse(message="Stop command sent", cmd_id=cmd_id)
    except Exception as e:
        logger.error(f"❌ Failed to send stop command: {e}")
        raise HTTPException(status_code=500, detail="Failed to send command")


# ============================================================================
# C2 SERVER INTEGRATION
# ============================================================================

@router.post("/register")
async def c2_register_agent(agent_info: AgentInfoPayload, current_user: JWTPayload = Depends(get_current_user)):
    """Register new agent (SEC-004: requires authentication)"""
    c2 = _get_c2_server()
    agent_id = await c2.register_agent(agent_info.model_dump())
    logger.info(f"Agent registered by {current_user.username}: {agent_id}")
    return {"agent_id": agent_id, "encryption_key": c2.encryption_key.decode()}


@router.post("/beacon/{agent_id}")
async def c2_agent_beacon(agent_id: str, current_user: JWTPayload = Depends(get_current_user)):
    """Process agent beacon and return tasks (SEC-004: requires authentication)"""
    c2 = _get_c2_server()
    tasks = await c2.agent_beacon(agent_id)
    return {"tasks": tasks}


@router.post("/task/{task_id}/result", response_model=StatusResponse)
async def c2_task_result(task_id: str, result_data: TaskResultPayload, current_user: JWTPayload = Depends(get_current_user)):
    """Receive task result (SEC-004: requires authentication)"""
    c2 = _get_c2_server()
    await c2.task_result(task_id=task_id, result=result_data.result,
                         success=result_data.success)
    return StatusResponse(status="received")


@router.get("/agents")
async def list_agents(current_user=Depends(get_current_user)):
    """List all registered agents"""
    c2 = _get_c2_server()
    agents = []
    for agent_id in c2.agents.keys():
        try:
            status = await c2.get_agent_status(agent_id)
            agents.append(status)
        except Exception:
            pass
    return {"agents": agents}


@router.post("/agents/{agent_id}/task", response_model=TaskSubmitResponse)
async def submit_task_to_agent(
    agent_id: str, payload_data: TaskSubmitRequest, current_user=Depends(get_current_user)
):
    """Submit task to agent"""
    c2 = _get_c2_server()
    task_id = await c2.submit_task(
        agent_id=agent_id,
        task_type=payload_data.type,
        task_data=payload_data.data,
        priority=payload_data.priority
    )
    await _broadcast_log("C2", "INFO", f"Task sent to {agent_id}", {"task_id": task_id})
    return TaskSubmitResponse(task_id=task_id)


@router.delete("/agents/{agent_id}", response_model=StatusResponse)
async def kill_agent_endpoint(agent_id: str, current_user=Depends(get_current_user)):
    """Kill agent (self-destruct)"""
    c2 = _get_c2_server()
    await c2.kill_agent(agent_id)
    await _broadcast_log("C2", "CRITICAL", f"Kill signal sent to {agent_id}", {})
    return StatusResponse(status="termination signal sent")
