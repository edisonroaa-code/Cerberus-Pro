"""
Coverage Ledger - Registro central de cobertura.
Responde: ¿qué se probó? ¿qué se saltó? ¿por qué?
"""

from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timezone
from enum import Enum


class CoverageStatus(str, Enum):
    """Estado de cada vector/engine."""
    EXECUTED = "EXECUTED"
    QUEUED = "QUEUED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    PENDING = "PENDING"
    TIMEOUT = "TIMEOUT"


class VectorCoverageRecord(BaseModel):
    """Registro de un vector de ataque."""
    vector_id: str
    vector_name: str
    engine: str
    status: CoverageStatus
    inputs_found: int = 0
    inputs_tested: int = 0
    inputs_failed: int = 0
    duration_ms: int = 0
    error: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)


class EngineCoverageRecord(BaseModel):
    """Registro de un motor de escaneo."""
    engine_name: str
    status: CoverageStatus
    vectors_total: int
    vectors_executed: int = 0
    vectors_failed: int = 0
    duration_ms: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None
    

class PhaseCompletionRecord(BaseModel):
    """Registro de completitud de cada fase."""
    phase: str  # preflight, discovery, execution, escalation, correlation, verdict
    status: str  # completed, partially_completed, failed, timeout
    duration_ms: int
    start_time: datetime
    end_time: datetime
    items_processed: int = 0
    items_failed: int = 0
    notes: List[str] = Field(default_factory=list)


class ConclusiveBlocker(BaseModel):
    """Bloqueador que impide NO_VULNERABLE."""
    category: str  # missing_inputs, missing_deps, engine_failed, timeout, incomplete_vectors, etc.
    detail: str
    phase: str  # en qué fase se detectó
    recoverable: bool = False  # ¿se puede recuperar en próximo intento?
    evidence: Optional[str] = None


class CoverageLedger(BaseModel):
    """Libro mayor de cobertura - verdad única."""
    
    # Identidad
    scan_id: str
    target_url: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Presupuestos
    budget_max_time_ms: int
    budget_max_retries: int
    budget_max_parallel: int
    budget_max_phase_time_ms: int
    
    budget_spent_time_ms: int = 0
    budget_spent_retries: int = 0
    budget_spent_parallel_current: int = 0
    
    # Solicitud vs Ejecución
    engines_requested: List[str] = Field(
        description="Motores solicitados"
    )
    engines_executed: List[str] = Field(
        default_factory=list,
        description="Motores que lograron ejecutarse"
    )
    
    vectors_requested: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Por engine: lista de vectores solicitados"
    )
    
    # Cobertura de entrada
    inputs_found: int = 0
    inputs_tested: int = 0
    inputs_failed: int = 0
    
    # Registros granulares
    engine_records: List[EngineCoverageRecord] = Field(default_factory=list)
    vector_records: List[VectorCoverageRecord] = Field(default_factory=list)
    phase_records: List[PhaseCompletionRecord] = Field(default_factory=list)
    
    # Dependencias
    deps_requested: List[str] = Field(default_factory=list)
    deps_available: List[str] = Field(default_factory=list)
    deps_missing: List[str] = Field(default_factory=list)
    
    # Bloqueadores (verdad única de por qué no es NO_VULNERABLE)
    conclusive_blockers: List[ConclusiveBlocker] = Field(
        default_factory=list,
        description="Razones por las que no se puede declarar NO_VULNERABLE"
    )
    
    # Finales
    total_duration_ms: int = 0
    status: str = "in_progress"  # in_progress, completed, failed, timeout
    
    # Criterios de completitud
    model_config = ConfigDict(validate_assignment=True)
    
    def add_vector_record(self, record: VectorCoverageRecord) -> None:
        """Registra ejecución de un vector."""
        self.vector_records.append(record)
        if record.status == CoverageStatus.EXECUTED:
            self.inputs_found += record.inputs_found
            self.inputs_tested += record.inputs_tested
            self.inputs_failed += record.inputs_failed
    
    def add_engine_record(self, record: EngineCoverageRecord) -> None:
        """Registra ejecución de un motor."""
        self.engine_records.append(record)
        if record.status == CoverageStatus.EXECUTED and record.engine_name not in self.engines_executed:
            self.engines_executed.append(record.engine_name)
    
    def add_phase_record(self, record: PhaseCompletionRecord) -> None:
        """Registra completitud de una fase."""
        self.phase_records.append(record)
    
    def add_blocker(self, blocker: ConclusiveBlocker) -> None:
        """Añade un bloqueador conclusivo."""
        if blocker not in self.conclusive_blockers:
            self.conclusive_blockers.append(blocker)
    
    def is_engines_complete(self) -> bool:
        """¿Se ejecutaron todos los motores solicitados?"""
        return set(self.engines_executed) == set(self.engines_requested)
    
    def has_coverage_gaps(self) -> bool:
        """¿Hay huecos de cobertura?"""
        # Huecos: motores solicitados no ejecutados, dependencias faltantes, etc.
        missing_engines = set(self.engines_requested) - set(self.engines_executed)
        return len(missing_engines) > 0 or len(self.deps_missing) > 0
    
    def coverage_percentage(self) -> float:
        """Porcentaje de cobertura (0-100)."""
        if not self.engines_requested:
            return 0.0
        return (len(self.engines_executed) / len(self.engines_requested)) * 100
    
    def is_resource_exhausted(self) -> bool:
        """¿Se agotó el presupuesto de recursos?"""
    
    def add_vector_record(self, record: VectorCoverageRecord) -> None:
        """Registra ejecución de un vector."""
        self.vector_records.append(record)
        if record.status == CoverageStatus.EXECUTED:
            self.inputs_found += record.inputs_found
            self.inputs_tested += record.inputs_tested
            self.inputs_failed += record.inputs_failed
    
    def add_engine_record(self, record: EngineCoverageRecord) -> None:
        """Registra ejecución de un motor."""
        self.engine_records.append(record)
        if record.status == CoverageStatus.EXECUTED and record.engine_name not in self.engines_executed:
            self.engines_executed.append(record.engine_name)
    
    def add_phase_record(self, record: PhaseCompletionRecord) -> None:
        """Registra completitud de una fase."""
        self.phase_records.append(record)
    
    def add_blocker(self, blocker: ConclusiveBlocker) -> None:
        """Añade un bloqueador conclusivo."""
        if blocker not in self.conclusive_blockers:
            self.conclusive_blockers.append(blocker)
    
    def is_engines_complete(self) -> bool:
        """¿Se ejecutaron todos los motores solicitados?"""
        return set(self.engines_executed) == set(self.engines_requested)
    
    def has_coverage_gaps(self) -> bool:
        """¿Hay huecos de cobertura?"""
        # Huecos: motores solicitados no ejecutados, dependencias faltantes, etc.
        missing_engines = set(self.engines_requested) - set(self.engines_executed)
        return len(missing_engines) > 0 or len(self.deps_missing) > 0
    
    def coverage_percentage(self) -> float:
        """Porcentaje de cobertura (0-100)."""
        if not self.engines_requested:
            return 0.0
        return (len(self.engines_executed) / len(self.engines_requested)) * 100
    
    def is_resource_exhausted(self) -> bool:
        """¿Se agotó el presupuesto de recursos?"""
        return (
            self.budget_spent_time_ms >= self.budget_max_time_ms or
            self.budget_spent_retries >= self.budget_max_retries or
            self.budget_spent_parallel_current >= self.budget_max_parallel
        )
    
    def should_be_inconclusive(self) -> bool:
        """¿Debe ser forzado a INCONCLUSIVE por bloqueadores?"""
        return (
            len(self.conclusive_blockers) > 0 or
            self.inputs_tested == 0 or
            not self.is_engines_complete() or
            self.has_coverage_gaps()
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el ledger a un diccionario compatible con la DB (v1)."""
        return {
            "summary": {
                "scan_id": self.scan_id,
                "target_url": self.target_url,
                "inputs": {
                    "found": self.inputs_found,
                    "tested": self.inputs_tested,
                    "failed": self.inputs_failed,
                },
                "engines": {
                    "requested": self.engines_requested,
                    "executed": self.engines_executed,
                },
                "budget": {
                    "max_time_ms": self.budget_max_time_ms,
                    "spent_time_ms": self.budget_spent_time_ms,
                },
                "coverage_percentage": self.coverage_percentage(),
                "has_gaps": self.has_coverage_gaps(),
                "is_complete": self.is_engines_complete(),
                "should_be_inconclusive": self.should_be_inconclusive(),
            },
            "blockers": [b.model_dump() for b in self.conclusive_blockers],
            "phases": [p.model_dump() for p in self.phase_records],
            "vectors": [v.model_dump() for v in self.vector_records],
        }
