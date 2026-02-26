"""
Orquestador - Máquina de estados transparente.
Fases: preflight -> discovery -> execution -> escalation -> correlation -> verdict
Cada estado tiene entry/exit criteria y timeout.
"""

from enum import Enum
from typing import Dict, Any, Callable, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import asyncio
import logging

logger = logging.getLogger(__name__)


class OrchestratorPhase(str, Enum):
    """Fases del orquestador."""
    PREFLIGHT = "preflight"
    DISCOVERY = "discovery"
    EXECUTION = "execution"
    ESCALATION = "escalation"
    CORRELATION = "correlation"
    VERDICT = "verdict"


class PhaseExecution(BaseModel):
    """Estados de ejecución de una fase."""
    
    phase: OrchestratorPhase
    
    # Timestamps
    started_at: datetime
    ended_at: Optional[datetime] = None
    
    # Criterios
    entry_criteria_met: bool = False
    exit_criteria_met: bool = False
    
    # Detalles
    status: str = "running"  # running, completed, failed, timeout, skipped
    duration_ms: int = 0
    retry_count: int = 0
    
    # Configuración de timeout y retry
    timeout_ms: int = 60000  # default 60s
    max_retries: int = 3
    
    # Resultados
    items_processed: int = 0
    items_failed: int = 0
    errors: List[str] = Field(default_factory=list)


class OrchestratorPhaseContext(BaseModel):
    """Contexto compartido entre fases."""
    
    scan_id: str
    target_url: str
    
    # Estado global
    preflight_config: Dict[str, Any] = Field(default_factory=dict)
    discovered_endpoints: List[str] = Field(default_factory=list)
    discovered_params: Dict[str, List[str]] = Field(default_factory=dict)
    available_engines: List[str] = Field(default_factory=list)
    
    # Ejecución
    execution_results: Dict[str, Any] = Field(default_factory=dict)
    escalation_attempts: Dict[str, Any] = Field(default_factory=dict)
    
    # Correlación
    correlation_map: Dict[str, List[str]] = Field(default_factory=dict)
    
    # Presupuesto
    budget_consumed: Dict[str, int] = Field(
        default_factory=lambda: {
            "time_ms": 0,
            "retries": 0,
            "parallel_jobs": 0
        }
    )


class OrchestratorPhaseHandler(BaseModel):
    """Handler de una fase - define lógica y criterios."""
    
    phase: OrchestratorPhase
    description: str
    
    # Configuración
    timeout_ms: int
    max_retries: int
    run_in_parallel: bool = False
    
    # Criterios (como strings evaluables)
    entry_criteria: List[str] = Field(
        description="Condiciones que deben ser true para entrar"
    )
    exit_criteria: List[str] = Field(
        description="Condiciones que deben ser true para salir con éxito"
    )
    
    failure_blockers: List[str] = Field(
        default_factory=list,
        description="Si falla esta fase, qué bloqueadores añadir"
    )


class Orchestrator:
    """Máquina de estados del orquestador."""
    
    # Definiciones de fases
    PHASE_HANDLERS: Dict[OrchestratorPhase, OrchestratorPhaseHandler] = {
        OrchestratorPhase.PREFLIGHT: OrchestratorPhaseHandler(
            phase=OrchestratorPhase.PREFLIGHT,
            description="Validar prerrequisitos, config, dependencias",
            timeout_ms=30000,
            max_retries=2,
            entry_criteria=[
                "scan_id exists",
                "target_url is valid",
            ],
            exit_criteria=[
                "all dependencies checked",
                "config validated",
                "available_engines not empty"
            ],
            failure_blockers=[
                "missing_critical_deps",
                "invalid_config"
            ]
        ),
        
        OrchestratorPhase.DISCOVERY: OrchestratorPhaseHandler(
            phase=OrchestratorPhase.DISCOVERY,
            description="Descubrir endpoints, formularios, parámetros",
            timeout_ms=60000,
            max_retries=3,
            entry_criteria=[
                "preflight completed",
                "available_engines not empty"
            ],
            exit_criteria=[
                "target_url crawled",
                "discovered_endpoints not empty"
            ],
            failure_blockers=[
                "no_endpoints_found",
                "discovery_timeout"
            ]
        ),
        
        OrchestratorPhase.EXECUTION: OrchestratorPhaseHandler(
            phase=OrchestratorPhase.EXECUTION,
            description="Ejecutar payloads contra vectores descubiertos",
            timeout_ms=180000,  # 3 minutos
            max_retries=2,
            run_in_parallel=True,
            entry_criteria=[
                "discovery completed",
                "discovered_endpoints not empty",
                "discovered_params not empty"
            ],
            exit_criteria=[
                "all vectors tested OR budget exhausted"
            ],
            failure_blockers=[
                "execution_timeout",
                "incomplete_vectors"
            ]
        ),
        
        OrchestratorPhase.ESCALATION: OrchestratorPhaseHandler(
            phase=OrchestratorPhase.ESCALATION,
            description="Intentar escalación de privilegios/exfiltración",
            timeout_ms=120000,  # 2 minutos
            max_retries=1,
            entry_criteria=[
                "execution completed OR execution findings detected"
            ],
            exit_criteria=[
                "escalation_attempts completed OR no findings to escalate"
            ],
            failure_blockers=[
            ]  # Opcional
        ),
        
        OrchestratorPhase.CORRELATION: OrchestratorPhaseHandler(
            phase=OrchestratorPhase.CORRELATION,
            description="Correlacionar hallazgos entre motores",
            timeout_ms=30000,
            max_retries=1,
            entry_criteria=[
                "execution completed OR escalation completed"
            ],
            exit_criteria=[
                "findings correlated",
                "confidence levels assigned"
            ],
            failure_blockers=[
            ]
        ),
        
        OrchestratorPhase.VERDICT: OrchestratorPhaseHandler(
            phase=OrchestratorPhase.VERDICT,
            description="Emitir veredicto final",
            timeout_ms=15000,
            max_retries=1,
            entry_criteria=[
                "correlation completed OR all phases attempted"
            ],
            exit_criteria=[
                "verdict_issued"
            ],
            failure_blockers=[
            ]
        )
    }
    
    def __init__(self, scan_id: str, target_url: str):
        self.scan_id = scan_id
        self.target_url = target_url
        self.context = OrchestratorPhaseContext(
            scan_id=scan_id,
            target_url=target_url
        )
        self.phase_executions: Dict[OrchestratorPhase, PhaseExecution] = {}
        self.current_phase: Optional[OrchestratorPhase] = None
        self.start_time = datetime.now(timezone.utc)
        logger.info(f"Orquestador inicializado para el escaneo {scan_id}")
    
    def get_phase_sequence(self) -> List[OrchestratorPhase]:
        """Retorna la secuencia de fases."""
        return [
            OrchestratorPhase.PREFLIGHT,
            OrchestratorPhase.DISCOVERY,
            OrchestratorPhase.EXECUTION,
            OrchestratorPhase.ESCALATION,
            OrchestratorPhase.CORRELATION,
            OrchestratorPhase.VERDICT,
        ]
    
    async def execute_phase(
        self,
        phase: OrchestratorPhase,
        phase_handler: Callable,
        context: OrchestratorPhaseContext
    ) -> PhaseExecution:
        """Ejecuta una fase con control de timeout, retry y criterios."""
        
        handler_config = self.PHASE_HANDLERS[phase]
        execution = PhaseExecution(
            phase=phase,
            started_at=datetime.now(timezone.utc),
            timeout_ms=handler_config.timeout_ms,
            max_retries=handler_config.max_retries
        )
        
        self.current_phase = phase
        self.phase_executions[phase] = execution
        
        logger.info(f"[{phase.value}] Iniciando fase...")
        
        # Verificar entry criteria
        execution.entry_criteria_met = self._check_entry_criteria(phase, context)
        if not execution.entry_criteria_met:
            logger.warning(f"[{phase.value}] Criterios de entrada no cumplidos")
            execution.status = "skipped"
            execution.ended_at = datetime.now(timezone.utc)
            execution.duration_ms = int(
                (execution.ended_at - execution.started_at).total_seconds() * 1000
            )
            return execution
        
        # Retry loop
        for attempt in range(1, handler_config.max_retries + 1):
            try:
                execution.retry_count = attempt
                
                # Ejecutar con timeout
                try:
                    result = await asyncio.wait_for(
                        phase_handler(context),
                        timeout=handler_config.timeout_ms / 1000.0
                    )
                    logger.info(f"[{phase.value}] Intento {attempt}/{handler_config.max_retries} completado con éxito")
                    
                    # Verificar exit criteria
                    execution.exit_criteria_met = self._check_exit_criteria(phase, context)
                    if execution.exit_criteria_met:
                        execution.status = "completed"
                        break
                    else:
                        logger.warning(f"[{phase.value}] Criterios de salida no cumplidos tras ejecución")
                        if attempt == handler_config.max_retries:
                            execution.status = "failed"
                            break
                
                except asyncio.TimeoutError:
                    logger.error(f"[{phase.value}] Tiempo de espera (Timeout) tras {handler_config.timeout_ms}ms")
                    execution.errors.append(f"Timeout after {handler_config.timeout_ms}ms")
                    if attempt == handler_config.max_retries:
                        execution.status = "timeout"
                    else:
                        logger.info(f"[{phase.value}] Reintentando (intento {attempt + 1}/{handler_config.max_retries})...")
                
            except Exception as e:
                logger.error(f"[{phase.value}] Excepción en ejecución: {str(e)}")
                execution.errors.append(str(e))
                if attempt == handler_config.max_retries:
                    execution.status = "failed"
        
        execution.ended_at = datetime.now(timezone.utc)
        execution.duration_ms = int(
            (execution.ended_at - execution.started_at).total_seconds() * 1000
        )
        
        # Actualizar contexto de presupuesto
        self.context.budget_consumed["time_ms"] = int(
            (datetime.now(timezone.utc) - self.start_time).total_seconds() * 1000
        )
        
        logger.info(f"[{phase.value}] Completado con estado: {execution.status}")
        return execution
    
    def _check_entry_criteria(self, phase: OrchestratorPhase, context: OrchestratorPhaseContext) -> bool:
        """Verifica entry criteria de una fase."""
        handler = self.PHASE_HANDLERS[phase]
        
        # Aquí se podrían evaluar las criteria de forma más sofisticada
        # Por ahora: lógica simple basada en fase anterior
        if phase == OrchestratorPhase.PREFLIGHT:
            return True
        
        phase_sequence = self.get_phase_sequence()
        try:
            phase_index = phase_sequence.index(phase)
        except ValueError:
            return False

        if phase_index <= 0:
            return True

        prev_phase = phase_sequence[phase_index - 1]
        prev_execution = self.phase_executions.get(prev_phase)
        
        return prev_execution is not None and prev_execution.status != "failed"
    
    def _check_exit_criteria(self, phase: OrchestratorPhase, context: OrchestratorPhaseContext) -> bool:
        """Verifica exit criteria de una fase."""
        # Lógica simplificada - mejorar según necesidad
        return True
    
    def get_phase_status_report(self) -> Dict[str, Any]:
        """Reporte de estado de todas las fases."""
        report = {
            "scan_id": self.scan_id,
            "total_duration_ms": int(
                (datetime.now(timezone.utc) - self.start_time).total_seconds() * 1000
            ),
            "phases": {}
        }
        
        for phase, execution in self.phase_executions.items():
            report["phases"][phase.value] = {
                "status": execution.status,
                "duration_ms": execution.duration_ms,
                "retry_count": execution.retry_count,
                "entry_criteria_met": execution.entry_criteria_met,
                "exit_criteria_met": execution.exit_criteria_met,
                "errors": execution.errors
            }
        
        return report
