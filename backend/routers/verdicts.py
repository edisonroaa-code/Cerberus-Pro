"""
Router de Veredictos - Emitir y reportar resultados.
POST /verdict/issue - Emitir veredicto based on ledger
GET /verdict/{scan_id} - Obtener veredicto de un scan
GET /verdict/{scan_id}/report - Reporte completo
GET /verdict/{scan_id}/report/executive - Resumen ejecutivo
GET /verdict/{scan_id}/report/coverage - Solo cobertura
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from core.verdict_contract import VerdictDictum, VerdictStatus
from core.coverage_ledger import CoverageLedger
from core.verdict_engine import VerdictEngine
from services.report_generator import ReportGenerator
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Storage en memoria para veredictos (en producción: BD)
_verdicts_store: Dict[str, VerdictDictum] = {}
_ledgers_store: Dict[str, CoverageLedger] = {}


class VerdictRequest(BaseModel):
    """Solicitud para emitir veredicto."""
    scan_id: str
    target_url: str
    ledger_data: Dict[str, Any]


class VerdictResponse(BaseModel):
    """Respuesta de veredicto."""
    status: str
    scan_id: str
    verdict: str
    confidence: float
    duration_seconds: float
    coverage_percentage: float
    conclusive_blockers: list


@router.post("/issue")
async def issue_verdict(request: VerdictRequest) -> VerdictResponse:
    """
    Emite veredicto basado en Coverage Ledger.
    Las reglas de gating son ESTRICTAS.
    """
    
    try:
        # Recrear ledger desde datos
        # (Nota: necesitaría deserialización completa en producción)
        ledger = CoverageLedger(
            scan_id=request.scan_id,
            target_url=request.target_url,
            budget_max_time_ms=300000,
            budget_max_retries=3,
            budget_max_parallel=5,
            budget_max_phase_time_ms=60000,
            engines_requested=request.ledger_data.get("engines_requested", [])
        )
        
        # Copiar datos
        ledger.engines_executed = request.ledger_data.get("engines_executed", [])
        ledger.inputs_found = request.ledger_data.get("inputs_found", 0)
        ledger.inputs_tested = request.ledger_data.get("inputs_tested", 0)
        ledger.deps_missing = request.ledger_data.get("deps_missing", [])
        
        # Emitir veredicto
        engine = VerdictEngine(ledger)
        verdict = engine.issue_verdict(
            scan_duration_ms=request.ledger_data.get("duration_ms", 0)
        )
        
        # Almacenar
        _verdicts_store[request.scan_id] = verdict
        _ledgers_store[request.scan_id] = ledger
        
        logger.info(f"Verdict issued for {request.scan_id}: {verdict.status.value}")
        
        return VerdictResponse(
            status="success",
            scan_id=request.scan_id,
            verdict=verdict.status.value,
            confidence=verdict.confidence_level,
            duration_seconds=verdict.total_duration_ms / 1000.0,
            coverage_percentage=ledger.coverage_percentage(),
            conclusive_blockers=verdict.conclusive_blockers
        )
    
    except Exception as e:
        logger.error(f"Error issuing verdict: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{scan_id}")
async def get_verdict(scan_id: str) -> Dict[str, Any]:
    """
    Obtiene veredicto de un scan.
    Incluye: status, reasoning, blockers, coverage.
    """
    
    if scan_id not in _verdicts_store:
        raise HTTPException(status_code=404, detail=f"Verdict not found for {scan_id}")
    
    verdict = _verdicts_store[scan_id]
    ledger = _ledgers_store[scan_id]
    
    return {
        "scan_id": scan_id,
        "verdict": verdict.status.value,
        "confidence": verdict.confidence_level,
        "primary_reason": {
            "category": verdict.primary_reason.category,
            "detail": verdict.primary_reason.detail
        },
        "coverage": {
            "percentage": ledger.coverage_percentage(),
            "engines_executed": len(ledger.engines_executed),
            "engines_requested": len(ledger.engines_requested),
            "inputs_tested": ledger.inputs_tested
        },
        "conclusive_blockers": [
            {
                "category": b.category,
                "detail": b.detail
            }
            for b in verdict.conclusive_blockers
        ] if verdict.conclusive_blockers else [],
        "issued_at": verdict.issued_at.isoformat()
    }


@router.get("/{scan_id}/report")
async def get_full_report(scan_id: str) -> Dict[str, Any]:
    """
    Reporte técnico completo.
    Incluye: engines, vectors, dependencies, phases, ressource usage.
    """
    
    if scan_id not in _verdicts_store:
        raise HTTPException(status_code=404, detail=f"Verdict not found for {scan_id}")
    
    verdict = _verdicts_store[scan_id]
    ledger = _ledgers_store[scan_id]
    
    reporter = ReportGenerator(ledger, verdict)
    return reporter.generate_detailed_report()


@router.get("/{scan_id}/report/executive")
async def get_executive_summary(scan_id: str) -> Dict[str, Any]:
    """
    Resumen ejecutivo para stakeholders.
    Veredicto + cobertura + recomendaciones.
    """
    
    if scan_id not in _verdicts_store:
        raise HTTPException(status_code=404, detail=f"Verdict not found for {scan_id}")
    
    verdict = _verdicts_store[scan_id]
    ledger = _ledgers_store[scan_id]
    
    reporter = ReportGenerator(ledger, verdict)
    return reporter.generate_executive_summary()


@router.get("/{scan_id}/report/coverage")
async def get_coverage_report(scan_id: str) -> Dict[str, Any]:
    """
    Solo análisis de cobertura.
    Por qué no es NO_VULNERABLE (si aplica).
    """
    
    if scan_id not in _ledgers_store:
        raise HTTPException(status_code=404, detail=f"Verdict not found for {scan_id}")
    
    ledger = _ledgers_store[scan_id]
    
    return {
        "scan_id": scan_id,
        "coverage_percentage": ledger.coverage_percentage(),
        "engines": {
            "requested": ledger.engines_requested,
            "executed": ledger.engines_executed,
            "missing": list(set(ledger.engines_requested) - set(ledger.engines_executed))
        },
        "inputs": {
            "found": ledger.inputs_found,
            "tested": ledger.inputs_tested,
            "failed": ledger.inputs_failed
        },
        "dependencies": {
            "required": ledger.deps_requested,
            "available": ledger.deps_available,
            "missing": ledger.deps_missing
        },
        "conclusive_blockers": [
            {
                "category": b.category,
                "detail": b.detail,
                "phase": b.phase,
                "recoverable": b.recoverable
            }
            for b in ledger.conclusive_blockers
        ]
    }


@router.get("/{scan_id}/report/non-technical")
async def get_non_technical_summary(scan_id: str) -> Dict[str, Any]:
    """
    Resumen para no-técnicos.
    Lenguaje simple, sin jerga de seguridad.
    """
    
    if scan_id not in _verdicts_store:
        raise HTTPException(status_code=404, detail=f"Verdict not found for {scan_id}")
    
    verdict = _verdicts_store[scan_id]
    ledger = _ledgers_store[scan_id]
    
    reporter = ReportGenerator(ledger, verdict)
    return reporter.generate_non_technical_summary()


@router.get("/stats")
async def verdict_statistics() -> Dict[str, Any]:
    """
    Estadísticas de veredictos emitidos.
    """
    
    verdict_counts = {
        "VULNERABLE": 0,
        "NO_VULNERABLE": 0,
        "INCONCLUSIVE": 0
    }
    
    for verdict in _verdicts_store.values():
        verdict_counts[verdict.status.value] += 1
    
    return {
        "total_verdicts": len(_verdicts_store),
        "by_status": verdict_counts,
        "scans": list(_verdicts_store.keys())
    }
