"""
Startup Dependency Health Check — Fase 5: Estabilidad Técnica.

Verifica la disponibilidad de módulos críticos al arranque del sistema.
Se invoca opcionalmente desde lifespan() en ares_api.py.
"""

import logging
import importlib
from typing import Dict, List, Tuple

logger = logging.getLogger("cerberus.core.startup_checks")

# Módulos críticos y sus rutas de importación
CRITICAL_MODULES: List[Tuple[str, str, str]] = [
    # (nombre_legible, ruta_import, descripción)
    ("CoverageLedger", "backend.core.coverage_ledger", "Coverage tracking"),
    ("VerdictEngine", "backend.core.verdict_engine", "Verdict gating logic"),
    ("Orchestrator FSM", "backend.core.orchestrator_fsm", "Phase state machine"),
    ("ScanManager", "backend.core.scan_manager", "Scan lifecycle manager"),
    ("PolicyEngine", "backend.governance.policy_engine", "Authorization policies"),
]

OPTIONAL_MODULES: List[Tuple[str, str, str]] = [
    ("WAF Detective", "backend.core.waf_detective", "WAF fingerprinting"),
    ("ChainOrchestrator", "backend.core.chain_orchestrator", "Exploitation chains"),
    ("EngineOrchestrator", "backend.engines.orchestrator", "Multi-engine scanning"),
    ("RedTeamReport", "backend.reporting.red_team_report", "Report generation"),
    ("ResourceEscalation", "backend.core.resource_escalation", "Resource scaling"),
    ("PostgresStore", "backend.db.postgres_store", "PostgreSQL persistence"),
]


def run_dependency_healthcheck() -> Dict[str, any]:
    """
    Ejecuta health-check de dependencias al startup.
    
    Returns:
        Dict con resultados: {
            "critical_ok": bool,
            "critical": [{"name": str, "status": "ok"|"missing", "module": str}],
            "optional": [{"name": str, "status": "ok"|"missing", "module": str}],
        }
    """
    results = {
        "critical_ok": True,
        "critical": [],
        "optional": [],
    }

    logger.info("=" * 60)
    logger.info("🔍 DEPENDENCY HEALTH CHECK")
    logger.info("=" * 60)

    # Check critical modules
    for name, module_path, description in CRITICAL_MODULES:
        try:
            importlib.import_module(module_path)
            results["critical"].append({"name": name, "status": "ok", "module": module_path})
            logger.info(f"  ✅ {name} ({description})")
        except ImportError as e:
            results["critical"].append({"name": name, "status": "missing", "module": module_path, "error": str(e)})
            results["critical_ok"] = False
            logger.error(f"  ❌ {name} ({description}) — {e}")

    # Check optional modules
    for name, module_path, description in OPTIONAL_MODULES:
        try:
            importlib.import_module(module_path)
            results["optional"].append({"name": name, "status": "ok", "module": module_path})
            logger.info(f"  ✅ {name} ({description})")
        except ImportError as e:
            results["optional"].append({"name": name, "status": "missing", "module": module_path, "error": str(e)})
            logger.warning(f"  ⚠️  {name} ({description}) — not available")

    # Summary
    critical_count = sum(1 for r in results["critical"] if r["status"] == "ok")
    optional_count = sum(1 for r in results["optional"] if r["status"] == "ok")
    
    logger.info("-" * 60)
    logger.info(f"  Critical: {critical_count}/{len(CRITICAL_MODULES)}")
    logger.info(f"  Optional: {optional_count}/{len(OPTIONAL_MODULES)}")
    
    if results["critical_ok"]:
        logger.info("  🟢 System ready")
    else:
        logger.error("  🔴 CRITICAL DEPENDENCIES MISSING — system may not function correctly")
    
    logger.info("=" * 60)

    return results
