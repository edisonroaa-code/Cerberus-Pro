"""
Jules Agent Router — (Phase 1: Copilot/Natural Language Parser)
Exposes an endpoint to translate natural language commands into actionable scan jobs.
"""

import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auth_security import JWTPayload, get_current_user

# Lazy import to avoid circular dependencies
def _get_cortex():
    from backend.core import cortex_ai
    return cortex_ai

def _get_job_control_deps():
    from backend.ares_runtime import _job_control_runtime_deps
    return _job_control_runtime_deps()

logger = logging.getLogger("cerberus.routers.jules")
router = APIRouter()

class CopilotRequest(BaseModel):
    command: str
    autopilot: bool = True

class CopilotResponse(BaseModel):
    message: str
    scan_id: str
    job_config: Dict[str, Any]


@router.post("/copilot", response_model=CopilotResponse)
async def jules_copilot_execute(
    request: CopilotRequest,
    current_user: JWTPayload = Depends(get_current_user)
):
    """
    Jules Copilot Endpoint: Takes a natural language command and starts a Cerberus job.
    """
    logger.info(f"🤖 Jules received command from {current_user.username}: '{request.command}'")
    
    cortex_ai = _get_cortex()
    
    # 1. Parse natural language via Gemini
    parsed_config = await cortex_ai.jules_parse_natural_language_command(request.command)
    
    if not parsed_config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Jules no pudo interpretar el comando. Por favor, sé más específico sobre el objetivo (URL) y el tipo de escaneo."
        )
        
    target_url = parsed_config.get("target_url")
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Jules no detectó un objetivo (URL o IP) válido en tu comando."
        )

    # 2. Extract and format job parameters
    mode = parsed_config.get("mode", "web")
    vectors = parsed_config.get("vectors", ["SQLMAP"])
    profile = parsed_config.get("profile", "standard")
    
    # 3. Build unified config
    # We map 'stealth', 'fast', 'deep', 'standard' to levels/risks
    level = 2
    risk = 1
    delay = 0
    if profile == "stealth":
        delay = 2
        level = 1
    elif profile == "deep":
        level = 3
        risk = 2
    elif profile == "fast":
        level = 1
        
    cfg = {
        "mode": mode,
        "profile": profile,
        "policy": {
            "level": level,
            "risk": risk,
            "delay": delay,
            "threads": 2 if profile == "stealth" else 4
        }
    }
    
    if mode == "web":
         cfg["vectors"] = vectors
    else:
         cfg["engine"] = vectors[0] if vectors else "NMAP"
         cfg["ports"] = "top-100" if profile == "fast" else "top-1000"
         
    # 4. Enqueue Job
    deps = _get_job_control_deps()
    try:
        from backend.core.job_control_runtime import create_job
        job = await create_job(
            user_id=current_user.sub,
            target_url=target_url,
            autopilot=request.autopilot,
            cfg=cfg,
            deps=deps
        )
        scan_id = job.get("scan_id", "unknown")
        
        return CopilotResponse(
            message=parsed_config.get("reasoning", "Comando procesado correctamente."),
            scan_id=scan_id,
            job_config=cfg
        )
        
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error de validación: {val_err}"
        )
    except Exception as e:
        logger.error(f"Jules failed to enqueue job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocurrió un error interno al intentar crear el trabajo."
        )
