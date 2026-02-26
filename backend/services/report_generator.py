"""
Reporter mejorado - Muestra siempre por qué.
Exporta coverage + conclusive_blockers.
Nunca "safe" si es inconcluso.
"""

from typing import Dict, Any, List
from backend.core.verdict_contract import VerdictDictum, VerdictStatus
from backend.core.coverage_ledger import CoverageLedger, ConclusiveBlocker
from backend.core.verdict_engine import VerdictEngine
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generador de reportes transparentes."""
    
    def __init__(self, ledger: CoverageLedger, verdict: VerdictDictum, output_dir: str = "reports"):
        self.ledger = ledger
        self.verdict = verdict
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_executive_summary(self) -> Dict[str, Any]:
        """Resumen ejecutivo con veredicto y cobertura."""
        
        return {
            "scan_metadata": {
                "scan_id": self.verdict.scan_id,
                "issued_at": self.verdict.issued_at.isoformat(),
                "duration_seconds": self.verdict.total_duration_ms / 1000.0
            },
            
            "verdict": {
                "status": self.verdict.status.value,
                "confidence_level": self.verdict.confidence_level,
                "primary_reason": {
                    "category": self.verdict.primary_reason.category,
                    "detail": self.verdict.primary_reason.detail
                }
            },
            
            "coverage": {
                "percentage": self.ledger.coverage_percentage(),
                "engines": {
                    "requested": self.ledger.engines_requested,
                    "executed": self.ledger.engines_executed,
                    "count": f"{len(self.ledger.engines_executed)}/{len(self.ledger.engines_requested)}"
                },
                "inputs": {
                    "found": self.ledger.inputs_found,
                    "tested": self.ledger.inputs_tested,
                    "failed": self.ledger.inputs_failed
                }
            },
            
            "safety_assertion": self._safety_assertion(),
            
            "recommendations": self._generate_recommendations()
        }
    
    def generate_detailed_report(self) -> Dict[str, Any]:
        """Reporte completo con todos los detalles."""
        
        return {
            "metadata": {
                "scan_id": self.verdict.scan_id,
                "target_url": self.ledger.target_url,
                "started_at": self.ledger.created_at.isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "total_duration_ms": self.verdict.total_duration_ms
            },
            
            "verdict": {
                "status": self.verdict.status.value,
                "confidence": self.verdict.confidence_level,
                "issued_at": self.verdict.issued_at.isoformat()
            },
            
            "verdict_reasoning": {
                "primary_reason": {
                    "category": self.verdict.primary_reason.category,
                    "detail": self.verdict.primary_reason.detail,
                    "evidence": self.verdict.primary_reason.evidence
                },
                "secondary_reasons": [
                    {
                        "category": r.category,
                        "detail": r.detail
                    }
                    for r in self.verdict.secondary_reasons
                ] if self.verdict.secondary_reasons else []
            },
            
            "coverage_analysis": {
                "overall_percentage": self.ledger.coverage_percentage(),
                "engines": {
                    "requested": self.ledger.engines_requested,
                    "executed": self.ledger.engines_executed,
                    "missing": list(set(self.ledger.engines_requested) - set(self.ledger.engines_executed)),
                    "completion_percentage": (len(self.ledger.engines_executed) / max(len(self.ledger.engines_requested), 1)) * 100
                },
                "inputs": {
                    "total_found": self.ledger.inputs_found,
                    "total_tested": self.ledger.inputs_tested,
                    "total_failed": self.ledger.inputs_failed,
                    "success_rate": (self.ledger.inputs_tested / max(self.ledger.inputs_found, 1)) * 100 if self.ledger.inputs_found > 0 else 0.0
                },
                "vectors": {
                    "total_requested": sum(len(v) for v in self.ledger.vectors_requested.values()),
                    "total_tested": len([r for r in self.ledger.vector_records if r.status.value == "EXECUTED"]),
                    "by_engine": self._vectors_by_engine()
                }
            },
            
            "dependency_status": {
                "requested": self.ledger.deps_requested,
                "available": self.ledger.deps_available,
                "missing": self.ledger.deps_missing
            },
            
            "phase_execution": [
                {
                    "phase": record.phase,
                    "status": record.status,
                    "duration_ms": record.duration_ms,
                    "items_processed": record.items_processed,
                    "items_failed": record.items_failed
                }
                for record in self.ledger.phase_records
            ],
            
            "conclusive_blockers": [
                {
                    "category": blocker.category,
                    "detail": blocker.detail,
                    "phase": blocker.phase,
                    "recoverable": blocker.recoverable,
                    "evidence": blocker.evidence
                }
                for blocker in self.ledger.conclusive_blockers
            ],
            
            "resource_usage": {
                "time_spent_ms": self.ledger.budget_spent_time_ms,
                "time_limit_ms": self.ledger.budget_max_time_ms,
                "time_exhausted": self.ledger.budget_spent_time_ms >= self.ledger.budget_max_time_ms,
                "retries_spent": self.ledger.budget_spent_retries,
                "retries_limit": self.ledger.budget_max_retries,
                "parallel_jobs_max": self.ledger.budget_max_parallel
            }
        }
    
    def generate_non_technical_summary(self) -> Dict[str, Any]:
        """Resumen para no-técnicos."""
        
        verdict_friendly_names = {
            VerdictStatus.VULNERABLE: "🔴 VULNERABLE - Se encontró una falla de seguridad",
            VerdictStatus.NO_VULNERABLE: "🟢 SEGURO - Análisis completo sin hallazgos",
            VerdictStatus.INCONCLUSIVE: "🟡 INCONCLUSO - No se pudo completar análisis"
        }
        
        return {
            "verdict": verdict_friendly_names.get(self.verdict.status, "DESCONOCIDO"),
            
            "what_was_tested": {
                "number_of_security_engines": len(self.ledger.engines_executed),
                "web_inputs_tested": self.ledger.inputs_tested,
                "attack_vectors_tried": len([r for r in self.ledger.vector_records])
            },
            
            "what_coverage_achieved": f"{self.ledger.coverage_percentage():.1f}% of planned testing",
            
            "what_could_not_be_tested": self._non_technical_blockers(),
            
            "risk_level": self._compute_risk_level(),
            
            "next_steps": self._non_technical_recommendations()
        }
    
    def _safety_assertion(self) -> str:
        """Asserción de seguridad clara."""
        
        if self.verdict.status == VerdictStatus.VULNERABLE:
            return f"⚠️ VULNERABLE - {self.verdict.primary_reason.detail}"
        
        elif self.verdict.status == VerdictStatus.NO_VULNERABLE:
            return f"✅ NO VULNERABLE - Comprehensive testing completed ({self.ledger.coverage_percentage():.1f}% coverage, {self.ledger.inputs_tested} inputs tested)"
        
        else:  # INCONCLUSIVE
            blockers_text = ", ".join([b.category for b in self.ledger.conclusive_blockers[:3]])
            return f"❓ INCONCLUSIVE - Coverage gaps: {blockers_text}"
    
    def _generate_recommendations(self) -> List[str]:
        """Recomendaciones basadas en veredicto y cobertura."""
        
        recommendations = []
        
        if self.verdict.status == VerdictStatus.VULNERABLE:
            recommendations.append("🔴 Immediately patch or remove the vulnerable component")
            recommendations.append("Conduct post-analysis to understand the attack vector")
            recommendations.append("Review logs for potential exploitation")
        
        elif self.verdict.status == VerdictStatus.INCONCLUSIVE:
            for blocker in self.ledger.conclusive_blockers[:5]:
                recommendations.append(f"Address blocker: {blocker.detail}")
            
            if not self.ledger.is_engines_complete():
                missing = set(self.ledger.engines_requested) - set(self.ledger.engines_executed)
                recommendations.append(f"Enable/retry engines: {', '.join(missing)}")
            
            if self.ledger.inputs_tested == 0:
                recommendations.append("Ensure target is accessible and has discoverable inputs")
            
            if self.ledger.has_coverage_gaps():
                recommendations.append(f"Expand testing to cover all {len(self.ledger.engines_requested)} engines")
        
        else:  # NO_VULNERABLE
            recommendations.append("Continue monitoring for new vulnerabilities")
            recommendations.append("Maintain regular security testing schedule")
            recommendations.append("Keep dependencies and framework versions updated")
        
        return recommendations
    
    def _vectors_by_engine(self) -> Dict[str, int]:
        """Vectores testados por motor."""
        by_engine = {}
        for record in self.ledger.vector_records:
            by_engine[record.engine] = by_engine.get(record.engine, 0) + 1
        return by_engine
    
    def _non_technical_blockers(self) -> List[str]:
        """Bloqueadores en lenguaje no-técnico."""
        
        blockers = []
        
        if len(self.ledger.deps_missing) > 0:
            blockers.append(f"Missing tools: {', '.join(self.ledger.deps_missing)}")
        
        if not self.ledger.is_engines_complete():
            missing = set(self.ledger.engines_requested) - set(self.ledger.engines_executed)
            blockers.append(f"Incomplete engines: {', '.join(missing)}")
        
        if self.ledger.inputs_tested == 0:
            blockers.append("No web inputs found to test (blank page or no forms)")
        
        if self.ledger.is_resource_exhausted() and self.ledger.status != "completed":
            blockers.append("Testing interrupted due to resource limits")
        
        return blockers
    
    def _compute_risk_level(self) -> str:
        """Nivel de riesgo basado en veredicto y confianza."""
        
        if self.verdict.status == VerdictStatus.VULNERABLE:
            return "🔴 CRITICAL - Immediate action required"
        
        elif self.verdict.status == VerdictStatus.INCONCLUSIVE:
            return "🟡 MEDIUM - Incomplete testing, cannot confirm safety"
        
        else:  # NO_VULNERABLE
            if self.verdict.confidence_level >= 0.9:
                return "🟢 LOW - Comprehensive testing completed successfully"
            else:
                return "🟢 LOW (with caveats) - Tested but with some limitations"
    
    def _non_technical_recommendations(self) -> List[str]:
        """Recomendaciones para no-técnicos."""
        
        recs = []
        
        if self.verdict.status == VerdictStatus.VULNERABLE:
            recs.append("Contact development team immediately")
            recs.append("Plan deployment of security patch")
        
        elif self.verdict.status == VerdictStatus.INCONCLUSIVE:
            recs.append("Re-run full scan when blockers are resolved")
            recs.append("Consult security team about coverage gaps")
        
        else:
            recs.append("Continue with scheduled security reviews")
            recs.append("No immediate action required")
        
        return recs
    
    def export_to_json(self) -> str:
        """Exporta reporte completo a JSON."""
        full_report = self.generate_detailed_report()
        return json.dumps(full_report, indent=2, default=str)
    
    def save_json_report(self, filename: str = None) -> str:
        """Guarda reporte JSON a disco."""
        if filename is None:
            filename = f"report_{self.verdict.scan_id}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            f.write(self.export_to_json())
        
        logger.info(f"Report saved to {filepath}")
        return filepath
    
    def export_to_html(self) -> str:
        """Exporta reporte a HTML (stub)."""
        # Implementación completa en producción
        exec_summary = self.generate_executive_summary()
        return f"<html><body><h1>{exec_summary['verdict']['status']}</h1></body></html>"
    
    def generate_cytoscape_json(self, results: List[Dict]) -> str:
        """Generates JSON compatible with Cytoscape for visual attack flow."""
        nodes = []
        edges = []
        
        # Central node: Target
        nodes.append({"data": {"id": "target", "label": "Target Site", "type": "root"}})
        
        for i, r in enumerate(results):
            vec_id = f"vec_{i}"
            label = r.get("vector", "unknown")
            vuln = r.get("vulnerable", False)
            
            nodes.append({
                "data": {
                    "id": vec_id,
                    "label": label,
                    "vulnerable": vuln,
                    "type": "vector"
                }
            })
            edges.append({"data": {"source": "target", "target": vec_id}})
            
            if r.get("chained"):
                parent_id = f"vec_{i-1}" if i > 0 else "target"
                edges.append({"data": {"source": parent_id, "target": vec_id, "label": "chained"}})

        return json.dumps({"nodes": nodes, "edges": edges}, indent=2)

    async def generate_pdf_report(self, scan_id: str, results: List[Dict]) -> str:
        """Generates a PDF report using Weasyprint."""
        try:
            from weasyprint import HTML  # type: ignore
        except ImportError:
            return "weasyprint not installed"

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; padding: 40px; }}
                h1 {{ color: #2c3e50; }}
                .vuln {{ color: #e74c3c; font-weight: bold; }}
                .safe {{ color: #27ae60; }}
                .box {{ border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }}
            </style>
        </head>
        <body>
            <h1>Cerberus Pro v4.0 - Scan Report</h1>
            <p>Scan ID: {scan_id}</p>
            <p>Date: {datetime.now(timezone.utc).isoformat()}</p>
            <hr>
            <h2>Attack Vectors Summary</h2>
        """
        
        for r in results:
            status = "VULNERABLE" if r.get("vulnerable") else "SAFE"
            css_class = "vuln" if r.get("vulnerable") else "safe"
            html_content += f"""
            <div class="box">
                <h3>Vector: {r.get('vector')} (<span class="{css_class}">{status}</span>)</h3>
                <p>Evidence: {", ".join(r.get('evidence', [])) or 'None'}</p>
            </div>
            """
            
        html_content += "</body></html>"
        
        pdf_path = os.path.join(self.output_dir, f"report_{scan_id}.pdf")
        HTML(string=html_content).write_pdf(pdf_path)
        return pdf_path

