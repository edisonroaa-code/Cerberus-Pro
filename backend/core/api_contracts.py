"""
Centralized Pydantic models for all API request/response contracts.

This module provides typed request and response models for every router,
ensuring end-to-end type safety and automatic OpenAPI documentation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================================
# C2 / AGENT MANAGEMENT CONTRACTS
# ============================================================================

class AgentCreateRequest(BaseModel):
    """Request to create a new C2 agent."""
    agent_name: str = Field(..., min_length=1, max_length=128, description="Human-readable agent name")


class AgentCreateResponse(BaseModel):
    """Response after creating a C2 agent (includes one-time secret)."""
    agent_id: str
    name: str
    client_id: str
    client_secret: str = Field(..., description="One-time display; store securely")


class AgentStatusResponse(BaseModel):
    """Public-facing agent status."""
    agent_id: str
    name: str
    is_active: bool
    last_connected: Optional[datetime] = None
    ip_address: Optional[str] = None
    version: str = "1.0.0"


class AgentListResponse(BaseModel):
    agents: List[AgentStatusResponse]


class AgentInfoPayload(BaseModel):
    """Payload for C2 agent registration."""
    hostname: Optional[str] = None
    os: Optional[str] = None
    arch: Optional[str] = None
    username: Optional[str] = None
    pid: Optional[int] = None
    extra: Optional[Dict[str, Any]] = None


class TaskSubmitRequest(BaseModel):
    """Submit a task to a C2 agent."""
    type: str = Field(..., min_length=1, description="Task type identifier")
    data: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10)


class TaskSubmitResponse(BaseModel):
    task_id: str


class TaskResultPayload(BaseModel):
    """Result payload sent back by an agent."""
    result: Optional[Any] = None
    success: bool = False


class CommandSentResponse(BaseModel):
    message: str
    cmd_id: str


class StatusResponse(BaseModel):
    """Generic status response."""
    status: str


# ============================================================================
# OFFENSIVE ROUTER CONTRACTS
# ============================================================================

class ExploitRunRequest(BaseModel):
    """Request to execute a Metasploit exploit."""
    module: str = Field(..., description="Metasploit module path")
    target: str = Field(..., description="Target host")
    port: int = Field(default=0, description="Target port")
    payload: str = Field(default="generic/shell_reverse_tcp", description="Metasploit payload")
    options: Dict[str, Any] = Field(default_factory=dict)


class ExploitRunResponse(BaseModel):
    result: Any
    session_id: Optional[int] = None


class SessionCommandRequest(BaseModel):
    command: str


class PayloadGenerateRequest(BaseModel):
    """Configuration for payload generation."""
    type: str = Field(..., description="Payload type")
    details: Dict[str, Any] = Field(default_factory=dict, description="Generation details")
    format: str = Field(default="raw")
    platform: Optional[str] = None
    arch: Optional[str] = None


class PayloadGenerateResponse(BaseModel):
    payload_b64: str = Field(..., description="Base64-encoded payload")
    size: int
    type: str


class PrivescRequest(BaseModel):
    """Privilege escalation attempt configuration."""
    technique: str = Field(default="", description="Technique to exploit")
    exploit_index: int = Field(default=0, ge=0)
    auto: bool = False


class LateralMovementRequest(BaseModel):
    target_host: str
    method: str = "psexec"
    credentials: Optional[Dict[str, str]] = None


# ============================================================================
# ENGINES ROUTER CONTRACTS
# ============================================================================

class EngineInfo(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    enabled: bool = True


class EngineListResponse(BaseModel):
    engines: List[EngineInfo]


class ScanVector(BaseModel):
    parameter: str
    value: Optional[str] = None
    type: str = "GET"


class ScanRequest(BaseModel):
    target: str
    vectors: List[ScanVector]
    engines: Optional[List[str]] = None


class FindingItem(BaseModel):
    engine: str
    severity: str
    description: str
    evidence: Optional[str] = None


class ScanResponse(BaseModel):
    findings: List[FindingItem]
    count: int


# ============================================================================
# HISTORY ROUTER CONTRACTS
# ============================================================================

class HistorySummaryItem(BaseModel):
    """Summary of a single scan history entry."""
    id: str
    timestamp: Optional[str] = None
    target: Optional[str] = None
    vulnerable: Optional[bool] = None
    verdict: Optional[str] = None
    conclusive: Optional[bool] = None
    count: Optional[int] = None
    profile: Optional[str] = None
    mode: Optional[str] = None
    kind: Optional[str] = None


class HistoryProfileResponse(BaseModel):
    id: str
    profile: str
    content: Any
