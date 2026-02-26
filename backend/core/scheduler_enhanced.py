"""
Scheduler mejorado - heartbeat por job, requeue automático, recuperación.
Sin jobs huérfanos ni trabajos trancos.
"""

from typing import Dict, List, Optional, Any, Callable
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from enum import Enum
import asyncio
import uuid
import logging

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """Estados de un job."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ORPHAN = "ORPHAN"  # Sin heartbeat
    RETRYING = "RETRYING"


class Job(BaseModel):
    """Unidad de trabajo."""
    
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    
    # Tarea
    task_name: str
    task_params: Dict[str, Any] = Field(default_factory=dict)
    
    # Estado
    status: JobStatus = JobStatus.QUEUED
    
    # Timeline
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    last_heartbeat_at: Optional[datetime] = None
    
    # Control
    max_retries: int = 3
    retry_count: int = 0
    timeout_ms: int = 60000
    
    # Resultado
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    def duration_ms(self) -> int:
        """Duración del job en ms."""
        if self.started_at is None:
            return 0
        end = self.ended_at or datetime.now(timezone.utc)
        return int((end - self.started_at).total_seconds() * 1000)
    
    def is_alive(self, heartbeat_timeout_ms: int = 30000) -> bool:
        """¿Job tiene heartbeat reciente?"""
        if self.status != JobStatus.RUNNING:
            return False
        if self.last_heartbeat_at is None:
            return False
        elapsed = (datetime.now(timezone.utc) - self.last_heartbeat_at).total_seconds() * 1000
        return elapsed < heartbeat_timeout_ms
    
    def is_timed_out(self) -> bool:
        """¿Job excedió timeout?"""
        if self.started_at is None:
            return False
        elapsed = (datetime.now(timezone.utc) - self.started_at).total_seconds() * 1000
        return elapsed > self.timeout_ms and self.status == JobStatus.RUNNING


class SchedulerJobQueue:
    """Cola de jobs con control de estado."""
    
    def __init__(self, max_parallel: int = 10, heartbeat_timeout_ms: int = 30000):
        self.max_parallel = max_parallel
        self.heartbeat_timeout_ms = heartbeat_timeout_ms
        
        # Almacenamiento
        self.jobs: Dict[str, Job] = {}  # job_id -> Job
        self.queue: List[str] = []  # job_ids en queue
        self.running: Dict[str, Job] = {}  # job_id -> Job running
        
        self.health_check_task: Optional[asyncio.Task] = None
        logger.info(f"Scheduler initialized: max_parallel={max_parallel}")
    
    def enqueue(self, job: Job) -> str:
        """Encola un job."""
        self.jobs[job.job_id] = job
        self.queue.append(job.job_id)
        logger.info(f"Job {job.job_id} enqueued: {job.task_name}")
        return job.job_id
    
    def dequeue(self) -> Optional[Job]:
        """Desencola el próximo job si hay capacidad."""
        if len(self.queue) == 0 or len(self.running) >= self.max_parallel:
            return None
        
        job_id = self.queue.pop(0)
        job = self.jobs[job_id]
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        self.running[job_id] = job
        logger.info(f"Job {job_id} dequeued and started")
        return job
    
    def heartbeat(self, job_id: str) -> bool:
        """Registra heartbeat de un job."""
        if job_id not in self.running:
            logger.warning(f"Heartbeat from unknown job {job_id}")
            return False
        
        job = self.running[job_id]
        job.last_heartbeat_at = datetime.now(timezone.utc)
        return True
    
    def job_completed(self, job_id: str, result: Dict[str, Any]) -> bool:
        """Marca un job como completado."""
        if job_id not in self.running:
            return False
        
        job = self.running[job_id]
        job.status = JobStatus.COMPLETED
        job.result = result
        job.ended_at = datetime.now(timezone.utc)
        del self.running[job_id]
        logger.info(f"Job {job_id} completed in {job.duration_ms()}ms")
        return True
    
    def job_failed(self, job_id: str, error: str, retry: bool = True) -> bool:
        """Marca un job como fallido."""
        if job_id not in self.running:
            return False
        
        job = self.running[job_id]
        job.error = error
        job.ended_at = datetime.now(timezone.utc)
        del self.running[job_id]
        
        # Reintentar si disponible
        if retry and job.retry_count < job.max_retries:
            job.retry_count += 1
            job.status = JobStatus.RETRYING
            self.queue.append(job_id)
            logger.info(f"Job {job_id} marked for retry ({job.retry_count}/{job.max_retries})")
            return True
        else:
            job.status = JobStatus.FAILED
            logger.error(f"Job {job_id} failed: {error}")
            return False
    
    async def health_check(self) -> None:
        """Verificación periódica de salud de jobs."""
        while True:
            await asyncio.sleep(5)  # Cada 5 segundos
            
            now = datetime.now(timezone.utc)
            orphans = []
            timeouts = []
            
            # Detectar huérfanos (sin heartbeat)
            for job_id, job in list(self.running.items()):
                if not job.is_alive(self.heartbeat_timeout_ms):
                    orphans.append(job_id)
                    logger.warning(f"Job {job_id} is orphan (no heartbeat)")
                
                # Detectar timeouts
                if job.is_timed_out():
                    timeouts.append(job_id)
                    logger.warning(f"Job {job_id} timed out")
            
            # Requeue hué rfanos
            for job_id in orphans:
                job = self.running.pop(job_id)
                job.status = JobStatus.ORPHAN
                if job.retry_count < job.max_retries:
                    job.retry_count += 1
                    job.status = JobStatus.RETRYING
                    self.queue.append(job_id)
                    logger.info(f"Orphan job {job_id} requeued")
                else:
                    job.status = JobStatus.FAILED
                    logger.error(f"Orphan job {job_id} exhausted retries")
            
            # Matar jobs con timeout
            for job_id in timeouts:
                job = self.running.pop(job_id)
                job.status = JobStatus.TIMEOUT
                job.ended_at = datetime.now(timezone.utc)
                if job.retry_count < job.max_retries:
                    job.retry_count += 1
                    job.status = JobStatus.RETRYING
                    self.queue.append(job_id)
                    logger.info(f"Timeout job {job_id} requeued")
                else:
                    logger.error(f"Timeout job {job_id} exhausted retries")
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Estado de la cola."""
        return {
            "queued_jobs": len(self.queue),
            "running_jobs": len(self.running),
            "total_jobs": len(self.jobs),
            "capacity_remaining": self.max_parallel - len(self.running),
            "jobs": {
                "queued": self.queue,
                "running": list(self.running.keys()),
                "completed": [
                    job_id for job_id, job in self.jobs.items()
                    if job.status == JobStatus.COMPLETED
                ]
            }
        }
    
    def get_job_info(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Info de un job específico."""
        if job_id not in self.jobs:
            return None
        
        job = self.jobs[job_id]
        return {
            "job_id": job_id,
            "task_name": job.task_name,
            "status": job.status.value,
            "duration_ms": job.duration_ms(),
            "retry_count": job.retry_count,
            "error": job.error,
            "result_keys": list(job.result.keys()) if job.result else []
        }
    
    async def recovery_at_startup(self) -> None:
        """Recuperación de jobs al iniciar."""
        logger.info("Running scheduler recovery at startup...")
        
        # Resetear jobs que corrían pero no completaron
        for job in self.jobs.values():
            if job.status in [JobStatus.RUNNING, JobStatus.RETRYING]:
                if job.retry_count < job.max_retries:
                    job.retry_count += 1
                    job.status = JobStatus.QUEUED
                    if job.job_id not in self.queue:
                        self.queue.append(job.job_id)
                    logger.info(f"Recovered job {job.job_id} marked for retry")
                else:
                    job.status = JobStatus.FAILED
                    logger.error(f"Job {job.job_id} exhausted retries at startup")
        
        logger.info(f"Recovery complete: {len(self.queue)} jobs in queue")
    
    async def start_health_monitoring(self) -> None:
        """Inicia monitoreo de salud."""
        if self.health_check_task is None:
            self.health_check_task = asyncio.create_task(self.health_check())
            logger.info("Health monitoring started")
    
    async def stop_health_monitoring(self) -> None:
        """Para monitoreo de salud."""
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
            logger.info("Health monitoring stopped")


# Singleton scheduler global
_scheduler_instance: Optional[SchedulerJobQueue] = None

def get_scheduler(max_parallel: int = 10) -> SchedulerJobQueue:
    """Obtiene la instancia singleton del scheduler."""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = SchedulerJobQueue(max_parallel=max_parallel)
    return _scheduler_instance

