# API-001: DEPRECATED — This router is NOT mounted in ares_api.py.
# The canonical scan endpoints live directly in ares_api.py (@app.post("/scan/start") etc.)
# TODO: Either mount this router or delete it during ARCH-002 refactor.
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, HttpUrl
import uuid
import logging

from backend.core.scan_manager import ScanManager

router = APIRouter()
logger = logging.getLogger("cerberus.api.scan")

class ScanRequest(BaseModel):
    target_url: str
    profile: str = "default"

@router.get("/module/status")
async def scan_status_module():
    return {"ok": True, "module": "scan"}

@router.post("/module/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a comprehensive scan (Discovery -> Execution -> Escalation -> Reporting).
    """
    scan_id = str(uuid.uuid4())
    logger.info(f"Received scan request for {request.target_url} (ID: {scan_id})")
    
    try:
        manager = ScanManager(target_url=request.target_url, scan_id=scan_id)
        
        # Run scan in background
        background_tasks.add_task(manager.run_scan)
        
        return {
            "status": "accepted",
            "scan_id": scan_id,
            "message": "Scan started in background"
        }
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))
