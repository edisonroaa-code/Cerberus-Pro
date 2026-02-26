"""
Motor de veredictos - Lógica de gating con reglas estrictas.
Sin ambigüedad, sin excepciones.
"""

from typing import List, Dict, Any, Optional
from backend.core.verdict_contract import VerdictStatus, VerdictDictum, VerdictReason, VERDICT_GATING_RULES
from backend.core.coverage_ledger import CoverageLedger, ConclusiveBlocker
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class VerdictEngine:
    """Motor de veredictos con gating transparente."""
    
    def __init__(self, ledger: CoverageLedger):
        self.ledger = ledger
        self.findings: List[Dict[str, Any]] = []
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Registra un hallazgo."""
        self.findings.append(finding)
        logger.info(f"Finding added: {finding.get('vector')} - {finding.get('type')}")
        self._add_to_timeline("finding_discovered", f"Found {finding.get('type')} in {finding.get('vector')}")

    def _add_to_timeline(self, event: str, detail: str) -> None:
        """Añade un hito al timeline temporal."""
        if not hasattr(self, "timeline"):
            self.timeline: List[Dict[str, Any]] = []
        
        self.timeline.append({
            "event": event,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    
    def issue_verdict(self, scan_duration_ms: int) -> VerdictDictum:
        """Emite veredicto final basado en Coverage Ledger y reglas estrictas."""
        
        gating = self._build_gating_snapshot()

        logger.info("=== ISSUING VERDICT ===")
        logger.info(f"Coverage: {self.ledger.coverage_percentage():.1f}%")
        logger.info(f"Inputs tested: {self.ledger.inputs_tested}")
        logger.info(f"Engines: {self.ledger.engines_executed}/{len(self.ledger.engines_requested)}")
        logger.info(f"Blockers: {len(self.ledger.conclusive_blockers)}")
        logger.info(f"Gating snapshot: {gating}")
        
        # Paso 1: ¿Hay hallazgos confirmados?
        if len(self.findings) > 0:
            return self._verdict_vulnerable(scan_duration_ms)
        
        # Paso 2: ¿Hay bloqueadores que fuercen INCONCLUSIVE?
        blockers_evaluation = self._evaluate_blockers(gating_snapshot=gating)
        
        if blockers_evaluation["should_be_inconclusive"]:
            return self._verdict_inconclusive(scan_duration_ms, blockers_evaluation)
        
        # Paso 3: ¿Cumple criterios para NO_VULNERABLE?
        if self._meets_no_vulnerable_criteria(gating_snapshot=gating):
            return self._verdict_no_vulnerable(scan_duration_ms, blockers_evaluation)
        
        # Default: INCONCLUSIVE (fail-safe)
        logger.warning("Default to INCONCLUSIVE due to uncertainty")
        return self._verdict_inconclusive(
            scan_duration_ms,
            {
                "reasons": ["Uncertainty - could not confirm NO_VULNERABLE"],
                "should_be_inconclusive": True
            }
        )
    
    def _verdict_vulnerable(self, scan_duration_ms: int) -> VerdictDictum:
        """Emite veredicto VULNERABLE."""
        logger.info("VERDICT: VULNERABLE - Findings confirmed")
        
        # Encontrar el hallazgo más confiable
        best_finding = max(self.findings, key=lambda f: f.get("confidence", 0.0))
        
        verdict = VerdictDictum(
            status=VerdictStatus.VULNERABLE,
            primary_reason=VerdictReason(
                category="vulnerability_found",
                detail=f"Confirmed vulnerability: {best_finding.get('type')} in {best_finding.get('vector')}",
                evidence=[
                    f"Engine: {best_finding.get('engine')}",
                    f"Vector: {best_finding.get('vector')}",
                    f"Confidence: {best_finding.get('confidence', 0.0):.1%}",
                    f"Payload: {best_finding.get('payload', 'N/A')[:100]}"
                ],
                metric={
                    "finding_count": len(self.findings),
                    "best_confidence": best_finding.get("confidence", 0.0)
                }
            ),
            scan_id=self.ledger.scan_id,
            total_duration_ms=scan_duration_ms,
            engines_involved=self.ledger.engines_executed,
            vectors_tested=self._get_tested_vectors(),
            confidence_level=best_finding.get("confidence", 0.7),
            assumptions=[
                f"Coverage: {self.ledger.coverage_percentage():.1f}%",
                f"Inputs tested: {self.ledger.inputs_tested}"
            ],
            timeline=getattr(self, "timeline", [])
        )
        
        return verdict
    
    def _verdict_inconclusive(self, scan_duration_ms: int, evaluation: Dict[str, Any]) -> VerdictDictum:
        """Emite veredicto INCONCLUSIVE."""
        logger.info(f"VERDICT: INCONCLUSIVE - Reasons: {evaluation.get('reasons', [])}")
        
        # Razones primarias y secundarias
        primary_reason_text = evaluation["reasons"][0] if evaluation["reasons"] else "Unknown"
        
        verdict = VerdictDictum(
            status=VerdictStatus.INCONCLUSIVE,
            primary_reason=VerdictReason(
                category="coverage_blocked",
                detail=primary_reason_text,
                evidence=evaluation.get("reasons", [])
            ),
            secondary_reasons=[
                VerdictReason(
                    category="coverage_gap",
                    detail=reason,
                    evidence=[]
                )
                for reason in evaluation.get("reasons", [])[1:]
            ],
            scan_id=self.ledger.scan_id,
            total_duration_ms=scan_duration_ms,
            engines_involved=self.ledger.engines_executed,
            vectors_tested=self._get_tested_vectors(),
            conclusive_blockers=[str(b) for b in self.ledger.conclusive_blockers],
            confidence_level=0.0,  # INCONCLUSIVE = no confianza
            assumptions=[
                f"Coverage: {self.ledger.coverage_percentage():.1f}%",
                f"Blocker count: {len(self.ledger.conclusive_blockers)}"
            ],
            timeline=getattr(self, "timeline", [])
        )
        
        return verdict
    
    def _verdict_no_vulnerable(self, scan_duration_ms: int, evaluation: Dict[str, Any]) -> VerdictDictum:
        """Emite veredicto NO_VULNERABLE (estricto)."""
        logger.info("VERDICT: NO_VULNERABLE - Criteria met perfectly")
        
        verdict = VerdictDictum(
            status=VerdictStatus.NO_VULNERABLE,
            primary_reason=VerdictReason(
                category="no_vulnerability_found",
                detail="Comprehensive testing completed without finding vulnerabilities",
                evidence=[
                    f"Engines: {self.ledger.engines_executed} / {self.ledger.engines_requested}",
                    f"Vectors: {len(self._get_tested_vectors())} tested",
                    f"Inputs: {self.ledger.inputs_tested} tested",
                    f"Coverage: {self.ledger.coverage_percentage():.1f}%",
                    f"No blockers: {len(self.ledger.conclusive_blockers) == 0}"
                ],
                metric={
                    "engines_executed": len(self.ledger.engines_executed),
                    "inputs_tested": self.ledger.inputs_tested,
                    "coverage_percentage": self.ledger.coverage_percentage()
                }
            ),
            scan_id=self.ledger.scan_id,
            total_duration_ms=scan_duration_ms,
            engines_involved=self.ledger.engines_executed,
            vectors_tested=self._get_tested_vectors(),
            conclusive_blockers=[],
            confidence_level=0.95,  # Alta confianza si cumple criterios
            assumptions=[
                "Complete engine coverage",
                "All discovered inputs tested",
                "No critical dependencies missing",
                "No timeout on critical phases"
            ],
            timeline=getattr(self, "timeline", [])
        )
        
        return verdict
    
    def _build_gating_snapshot(self) -> Dict[str, Any]:
        requested = sorted({str(e).strip() for e in (self.ledger.engines_requested or []) if str(e).strip()})
        executed = sorted({str(e).strip() for e in (self.ledger.engines_executed or []) if str(e).strip()})

        return {
            "requested_engines": requested,
            "executed_engines": executed,
            "engines_complete_exact": requested == executed,
            "inputs_tested_positive": int(self.ledger.inputs_tested or 0) > 0,
            "deps_missing_empty": len(self.ledger.deps_missing or []) == 0,
            "conclusive_blockers_empty": len(self.ledger.conclusive_blockers or []) == 0,
            "coverage_gaps_empty": not bool(self.ledger.has_coverage_gaps()),
            "resource_exhausted": bool(self.ledger.is_resource_exhausted()),
            "status_completed": str(self.ledger.status or "").lower() == "completed",
            "findings_count": len(self.findings),
        }

    def _evaluate_blockers(self, gating_snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evalúa bloqueadores de NO_VULNERABLE."""
        snapshot = gating_snapshot or self._build_gating_snapshot()
        reasons = []

        def _add_reason(reason: str) -> None:
            if reason and reason not in reasons:
                reasons.append(reason)
        
        # Bloqueador 1: No hay inputs
        if not snapshot["inputs_tested_positive"]:
            _add_reason("inputs_tested == 0 (no inputs found/tested)")
        
        # Bloqueador 2: Dependencias faltantes
        if not snapshot["deps_missing_empty"]:
            _add_reason(f"deps_missing: {', '.join(self.ledger.deps_missing)}")
        
        # Bloqueador 3: Motores incompletos
        if not snapshot["engines_complete_exact"]:
            missing_engines = set(snapshot["requested_engines"]) - set(snapshot["executed_engines"])
            extra_engines = set(snapshot["executed_engines"]) - set(snapshot["requested_engines"])
            if missing_engines:
                _add_reason(f"engines_executed != engines_requested (missing: {', '.join(sorted(missing_engines))})")
            if extra_engines:
                _add_reason(f"engines_executed != engines_requested (unexpected: {', '.join(sorted(extra_engines))})")
        
        # Bloqueador 4: Huecos de cobertura
        if not snapshot["coverage_gaps_empty"]:
            _add_reason(f"coverage_gaps detected: {self.ledger.coverage_percentage():.1f}% complete")
        
        # Bloqueador 5: Recursos agotados SOLO si quedó incompleto.
        if snapshot["resource_exhausted"] and (not snapshot["status_completed"]):
            _add_reason("resource_exhausted_incomplete")
        
        # Bloqueador 6: Blockers explícitos en ledger
        if len(self.ledger.conclusive_blockers) > 0:
            for blocker in self.ledger.conclusive_blockers:
                _add_reason(f"[{blocker.category}] {blocker.detail}")
        
        return {
            "should_be_inconclusive": len(reasons) > 0,
            "reasons": reasons
        }
    
    def _meets_no_vulnerable_criteria(self, gating_snapshot: Optional[Dict[str, Any]] = None) -> bool:
        """Verifica criterios ESTRICTOS para NO_VULNERABLE."""
        snapshot = gating_snapshot or self._build_gating_snapshot()
        
        # Criterio 1: Sin bloqueadores conclusivos
        if not snapshot["conclusive_blockers_empty"]:
            logger.info(f"NO_VULNERABLE blocked: {len(self.ledger.conclusive_blockers)} conclusive_blockers")
            return False
        
        # Criterio 2: Debe haber inputs testados
        if not snapshot["inputs_tested_positive"]:
            logger.info("NO_VULNERABLE blocked: inputs_tested == 0")
            return False
        
        # Criterio 3: Todos los motores solicitados ejecutados
        if not snapshot["engines_complete_exact"]:
            logger.info(
                "NO_VULNERABLE blocked: engines_executed != engines_requested "
                f"(requested={snapshot['requested_engines']}, executed={snapshot['executed_engines']})"
            )
            return False
        
        # Criterio 4: Sin dependencias faltantes
        if not snapshot["deps_missing_empty"]:
            logger.info(f"NO_VULNERABLE blocked: missing deps: {self.ledger.deps_missing}")
            return False
        
        # Criterio 5: Sin huecos de cobertura
        if not snapshot["coverage_gaps_empty"]:
            logger.info("NO_VULNERABLE blocked: coverage gaps present")
            return False
        
        logger.info("NO_VULNERABLE criteria met!")
        return True
    
    def _get_tested_vectors(self) -> List[str]:
        """Retorna lista de vectores testados."""
        vectors = set()
        for record in self.ledger.vector_records:
            vectors.add(record.vector_name)
        return list(vectors)
    
    def generate_verdict_report(self, verdict: VerdictDictum) -> Dict[str, Any]:
        """Genera reporte legible del veredicto."""
        
        report = {
            "verdict": verdict.status.value,
            "scan_id": verdict.scan_id,
            "issued_at": verdict.issued_at.isoformat(),
            "duration_seconds": verdict.total_duration_ms / 1000.0,
            
            "primary_reason": {
                "category": verdict.primary_reason.category,
                "detail": verdict.primary_reason.detail,
                "metric": verdict.primary_reason.metric
            },
            
            "coverage": {
                "engines": {
                    "requested": self.ledger.engines_requested,
                    "executed": self.ledger.engines_executed,
                    "percentage": self.ledger.coverage_percentage()
                },
                "inputs": {
                    "found": self.ledger.inputs_found,
                    "tested": self.ledger.inputs_tested,
                    "failed": self.ledger.inputs_failed
                },
                "vectors_tested": len(verdict.vectors_tested)
            },
            
            "confidence": verdict.confidence_level,
            
            "blockers": verdict.conclusive_blockers if verdict.conclusive_blockers else None,
        }
        
        if verdict.secondary_reasons:
            report["secondary_reasons"] = [
                {
                    "category": r.category,
                    "detail": r.detail
                }
                for r in verdict.secondary_reasons
            ]
        
        return report
