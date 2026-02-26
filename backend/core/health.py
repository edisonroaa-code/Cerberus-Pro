"""
Health Endpoints - Estado operativo completo.
Refleja: worker activo, cola viva, jobs running/queued, self-heal.
"""

from typing import Dict, Any
from datetime import datetime, timezone
from core.scheduler_enhanced import get_scheduler
import logging

logger = logging.getLogger(__name__)


class HealthStatus:
    """Reporte de salud del sistema."""
    
    def __init__(self):
        self.scheduler = get_scheduler()
        self.last_health_check = None
        self.self_heal_executed_count = 0
    
    def get_full_health(self) -> Dict[str, Any]:
        """Salud completa del sistema."""
        self.last_health_check = datetime.now(timezone.utc)
        scheduler_status = self.scheduler.get_queue_status()
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": self._compute_overall_status(scheduler_status),
            
            "scheduler": {
                "worker_active": len(scheduler_status["running_jobs"]) > 0,
                "queue_alive": len(scheduler_status["queued_jobs"]) > 0 or len(scheduler_status["running_jobs"]) > 0,
                "jobs": {
                    "queued": scheduler_status["queued_jobs"],
                    "running": scheduler_status["running_jobs"],
                    "capacity_remaining": scheduler_status["capacity_remaining"]
                },
                "total_jobs": scheduler_status["total_jobs"]
            },
            
            "self_heal": {
                "executed_count": self.self_heal_executed_count,
                "last_execution": self.last_health_check.isoformat() if self.last_health_check else None
            },
            
            "services": {
                "available": True,  # Expandir con checks reales
                "response_time_ms": 0
            }
        }
    
    def _compute_overall_status(self, scheduler_status: Dict[str, Any]) -> str:
        """Determina estado general."""
        if len(scheduler_status["running_jobs"]) == 0 and len(scheduler_status["queued_jobs"]) == 0:
            return "IDLE"
        elif len(scheduler_status["running_jobs"]) > 0:
            return "ACTIVE"
        else:
            return "QUEUED"
    
    def get_scheduler_health(self) -> Dict[str, Any]:
        """Solo salud del scheduler."""
        status = self.scheduler.get_queue_status()
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "queue_length": status["queued_jobs"],
            "running_jobs": status["running_jobs"],
            "capacity_remaining": status["capacity_remaining"],
            "total_tracked_jobs": status["total_jobs"]
        }
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Detalles de la cola."""
        return self.scheduler.get_queue_status()
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Estado de un job específico."""
        info = self.scheduler.get_job_info(job_id)
        if info is None:
            return {"error": f"Job {job_id} not found"}
        return info
    
    async def perform_self_heal(self) -> Dict[str, Any]:
        """Ejecuta auto-reparación."""
        logger.info("Performing system self-heal...")
        
        # 1. Recuperación de jobs huérfanos
        orphan_recovery = await self._recover_orphans()
        
        # 2. Limpieza de deadlocks
        deadlock_recovery = await self._clear_deadlocks()
        
        # 3. Rebalanceo de carga
        rebalance = await self._rebalance_queue()
        
        self.self_heal_executed_count += 1
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "orphan_recovery": orphan_recovery,
            "deadlock_recovery": deadlock_recovery,
            "rebalance": rebalance,
            "self_heal_count": self.self_heal_executed_count
        }
    
    async def _recover_orphans(self) -> Dict[str, Any]:
        """Recupera jobs sin heartbeat."""
        logger.info("Recovering orphan jobs...")
        
        # Aquí se ejecutaría lógica de recuperación
        # Por ahora: stub
        return {
            "jobs_recovered": 0,
            "action": "recovery_completed"
        }
    
    async def _clear_deadlocks(self) -> Dict[str, Any]:
        """Limpia deadlocks."""
        logger.info("Clearing deadlocks...")
        
        # Stub
        return {
            "deadlocks_cleared": 0,
            "action": "deadlock_check_completed"
        }
    
    async def _rebalance_queue(self) -> Dict[str, Any]:
        """Rebalancea la cola."""
        logger.info("Rebalancing queue...")
        
        # Stub
        return {
            "jobs_rebalanced": 0,
            "action": "rebalance_completed"
        }


# Singleton health status
_health_instance = None

def get_health_status() -> HealthStatus:
    """Obtiene instancia singleton de HealthStatus."""
    global _health_instance
    if _health_instance is None:
        _health_instance = HealthStatus()
    return _health_instance

