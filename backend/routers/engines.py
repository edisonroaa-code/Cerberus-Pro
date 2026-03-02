from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio

from backend.engines import list_engines, get_engine, EngineOrchestrator
from auth_security import get_current_user, require_permission, Role, Permission
from fastapi import Depends

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    vectors: List[Dict]
    engines: Optional[List[str]] = None


@router.get("/", tags=["engines"])
async def engines_list(current_user=Depends(get_current_user)):
    return {"engines": list_engines()}


@router.get("/{engine_id}/status", tags=["engines"])
async def engine_status(engine_id: str, current_user=Depends(get_current_user)):
    engine = get_engine(engine_id)
    if not engine:
        raise HTTPException(status_code=404, detail="Engine not found")
    return engine.get_status()


@router.post("/scan", tags=["engines"])
async def orchestrated_scan(req: ScanRequest, current_user=Depends(require_permission(Permission.SCAN_CREATE))):
    # Use orchestrator to run selected engines (or all if None)
    orch = EngineOrchestrator(enabled_engines=req.engines if req.engines else None)
    findings = await orch.scan_all(req.target, req.vectors)
    return {"findings": [f.__dict__ for f in findings], "count": len(findings)}
