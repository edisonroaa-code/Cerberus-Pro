"""
Contrato único de veredictos - sin cajas negras.
VULNERABLE: hallazgo confirmado
NO_VULNERABLE: solo si cobertura completa y sin bloqueadores
INCONCLUSIVE: cualquier hueco de cobertura
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class VerdictStatus(str, Enum):
    """Estados de veredicto únicos y mutuamente excluyentes."""
    VULNERABLE = "VULNERABLE"
    NO_VULNERABLE = "NO_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerdictReason(BaseModel):
    """Razón estructurada del veredicto."""
    category: str = Field(
        ..., 
        description="Categoría: vulnerability_found, coverage_blocked, missing_inputs, missing_deps, timeout, resource_exhausted"
    )
    detail: str = Field(..., description="Detalle específico por qué llegó a este veredicto")
    evidence: List[str] = Field(default_factory=list, description="Referencias a pruebas/logs")
    metric: Optional[Dict[str, Any]] = Field(None, description="Métrica asociada")


class VerdictDictum(BaseModel):
    """Veredicto final - auditoria completa."""
    
    # Veredicto base
    status: VerdictStatus = Field(
        ..., 
        description="VULNERABLE | NO_VULNERABLE | INCONCLUSIVE"
    )
    
    # Razones (pueden ser múltiples para INCONCLUSIVE)
    primary_reason: VerdictReason
    secondary_reasons: List[VerdictReason] = Field(default_factory=list)
    
    # Timestamp y duración
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    total_duration_ms: int
    
    # Trazabilidad
    scan_id: str
    engines_involved: List[str] = Field(description="Motores que participaron")
    vectors_tested: List[str] = Field(description="Vectores de ataque probados")
    
    # Bloqueadores conclusivos (por qué no es NO_VULNERABLE)
    conclusive_blockers: List[str] = Field(
        default_factory=list,
        description="Lista de bloqueadores que fuerzan INCONCLUSIVE"
    )
    
    # Metadata operativa
    confidence_level: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0,
        description="Confianza del veredicto (0-1)"
    )
    assumptions: List[str] = Field(
        default_factory=list,
        description="Asunciones bajo las que se emitió el veredicto"
    )
    
    # Timeline de eventos clave (Análisis temporal)
    timeline: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Eventos clave con offset de tiempo"
    )


class VerdictGatingRule(BaseModel):
    """Regla de gating para cada veredicto."""
    
    verdict_type: VerdictStatus
    conditions: Dict[str, Any] = Field(
        description="Condiciones que deben cumplirse"
    )
    blockers_if_missing: List[str] = Field(
        default_factory=list,
        description="Bloqueadores si no se cumplen condiciones"
    )


# Reglas de gating centralizadas
VERDICT_GATING_RULES = {
    VerdictStatus.NO_VULNERABLE: {
        "required_conditions": {
            "conclusive_blockers_empty": "conclusive_blockers.length === 0",
            "inputs_tested_positive": "inputs_tested > 0",
            "engines_complete": "engines_executed == engines_requested",
            "no_vulnerabilities": "vulnerabilities_found == 0",
        },
        "description": "Estricto: solo si cobertura completa, sin hallazgos, sin bloqueadores"
    },
    VerdictStatus.VULNERABLE: {
        "required_conditions": {
            "finding_confirmed": "len(findings) > 0 AND confidence >= 0.7",
        },
        "description": "Hallazgo confirmado con confianza >= 70%"
    },
    VerdictStatus.INCONCLUSIVE: {
        "required_conditions": {
            "any_blocker_present": "conclusive_blockers.length > 0 OR coverage_gaps.length > 0",
        },
        "description": "Default safety: cualquier hueco de cobertura, dependencia faltante, timeout, etc."
    }
}
