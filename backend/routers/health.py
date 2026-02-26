"""
Router de Salud y Veredictos - Endpoints operativos.
GET /health - Estado completo
GET /health/scheduler - Estado del scheduler
GET /health/job/{job_id} - Estado de un job
POST /health/self-heal - Ejecutar auto-reparación
"""

from fastapi import APIRouter, HTTPException
from core.health import get_health_status
from core.verdict_engine import VerdictEngine
from typing import Dict, Any
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("")
async def full_health_check() -> Dict[str, Any]:
    """
    Endpoint de salud completa.
    Retorna: estado del worker, cola, jobs running/queued, self-heal status
    """
    health = get_health_status()
    return health.get_full_health()


@router.get("/scheduler")
async def scheduler_health() -> Dict[str, Any]:
    """
    Estado del scheduler: queue length, running jobs, capacity
    """
    health = get_health_status()
    return health.get_scheduler_health()


@router.get("/queue")
async def queue_status() -> Dict[str, Any]:
    """
    Detalles de la cola: jobs queued, running, completed
    """
    health = get_health_status()
    return health.get_queue_status()


@router.get("/job/{job_id}")
async def job_status(job_id: str) -> Dict[str, Any]:
    """
    Estado de un job específico
    """
    health = get_health_status()
    status = health.get_job_status(job_id)
    
    if "error" in status:
        raise HTTPException(status_code=404, detail=status["error"])
    
    return status


@router.post("/self-heal")
async def execute_self_heal() -> Dict[str, Any]:
    """
    Ejecuta auto-reparación del sistema:
    - Recupera jobs huérfanos
    - Limpia deadlocks
    - Rebalancea cola
    """
    health = get_health_status()
    result = await health.perform_self_heal()
    
    logger.info(f"Self-heal executed, count: {result.get('self_heal_count')}")
    return result


@router.get("/readiness")
async def readiness_check() -> Dict[str, str]:
    """
    Kubernetes readiness probe
    """
    health = get_health_status()
    status = health.get_full_health()
    
    is_ready = status.get("status") in ["ACTIVE", "QUEUED", "IDLE"]
    
    return {
        "ready": "yes" if is_ready else "no",
        "status": status.get("status")
    }


@router.get("/liveness")
async def liveness_check() -> Dict[str, str]:
    """
    Kubernetes liveness probe
    """
    return {
        "alive": "yes",
        "service": "verdict_engine"
    }
