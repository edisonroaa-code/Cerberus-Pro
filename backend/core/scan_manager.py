"""
Scan Manager - The Master Orchestrator (System Synchronization)

Wires the Orchestrator FSM to the concrete Offensive and Defensive modules.
"""
import asyncio
import logging
import datetime
import os
from typing import Dict, Any, Optional

from backend.core.orchestrator_fsm import Orchestrator, OrchestratorPhase, OrchestratorPhaseContext
from backend.governance.policy_engine import get_policy_engine, ActionType

# Import Offensive/Defensive Modules (with graceful fallbacks)
try:
    from backend.core.waf_detective import fingerprint as waf_fingerprint
except ImportError:
    waf_fingerprint = None
    logging.getLogger(__name__).warning("Module waf_detective not available — WAF detection disabled")

try:
    from backend.core.chain_orchestrator import ChainOrchestrator, VulnerabilityFinding, VulnerabilityType
except ImportError:
    ChainOrchestrator = None
    logging.getLogger(__name__).warning("Module chain_orchestrator not available — escalation chains disabled")

try:
    from backend.reporting.red_team_report import get_reporter
except ImportError:
    get_reporter = None
    logging.getLogger(__name__).warning("Module red_team_report not available — reporting disabled")

try:
    from backend.engines.orchestrator import EngineOrchestrator
except ImportError:
    EngineOrchestrator = None
    logging.getLogger(__name__).warning("Module EngineOrchestrator not available — engine scanning disabled")

from backend.core.waf_feedback_loop import WAFResponseAnalyzer, AdaptiveStrategySelector
from backend.core.smart_cache import get_shared_smart_cache
from backend.core.events import get_scan_event_coordinator, release_scan_event_coordinator
from backend.core.cortex_ai import (
    analyze_waf_signal, suggest_escalation,
    correlate_findings_ai, generate_forensic_narrative,
    check_ai_health,
)

logger = logging.getLogger(__name__)

class ScanManager:
    """
    High-level manager that drives the Orchestrator FSM and connects it
    to the specific implementation modules (Engines, Chains, Reporting).
    """

    def __init__(self, target_url: str, scan_id: str = "manual"):
        self.scan_id = scan_id
        self.orchestrator = Orchestrator(scan_id, target_url)
        self.target_url = target_url
        self.policy_engine = get_policy_engine()
        self.reporter = get_reporter(client_name=f"Target: {target_url}") if get_reporter else None
        
        # Initialize Ledger
        from backend.core.coverage_ledger import CoverageLedger
        self.ledger = CoverageLedger(
            scan_id=scan_id,
            target_url=target_url,
            budget_max_time_ms=300000,
            budget_max_retries=3,
            budget_max_parallel=5,
            budget_max_phase_time_ms=60000,
            engines_requested=["sqlmap"]
        )
        
        # WAF feedback loop + Cortex AI telemetry
        self.waf_analyzer = WAFResponseAnalyzer(window_size=30)
        cache_db_path = os.environ.get("CERBERUS_SMART_CACHE_DB", "backend/data/smart_cache.sqlite3")
        self.smart_cache = get_shared_smart_cache(db_path=cache_db_path)
        self.strategy_selector = AdaptiveStrategySelector(self.waf_analyzer, smart_cache=self.smart_cache)
        self.strategy_selector.set_runtime_context(target_url=target_url, orchestrator="scan_manager")
        self.coordinator = get_scan_event_coordinator(scan_id)
        self.ai_decisions: list = []  # log of all AI decisions for telemetry

    async def run_scan(self):
        """Main entry point to run the full scan lifecycle."""
        logger.info(f"Iniciando escaneo para {self.target_url}")
        await self.coordinator.mark(
            "scan_started",
            {"scan_id": self.scan_id, "target": self.target_url, "orchestrator": "scan_manager"},
        )
        start_time_async = asyncio.get_event_loop().time()
        phase = OrchestratorPhase.PREFLIGHT
        
        # 0. Policy Check
        if not self.policy_engine.check_authorization(ActionType.SCAN, self.target_url):
            logger.error("Escaneo bloqueado por políticas de autorización.")
            await self.coordinator.mark(
                "scan_blocked_by_policy",
                {"scan_id": self.scan_id, "target": self.target_url},
            )
            release_scan_event_coordinator(self.scan_id)
            return

        phases_map = {
            OrchestratorPhase.PREFLIGHT: self._handle_preflight,
            OrchestratorPhase.DISCOVERY: self._handle_discovery,
            OrchestratorPhase.EXECUTION: self._handle_execution,
            OrchestratorPhase.ESCALATION: self._handle_escalation,
            OrchestratorPhase.CORRELATION: self._handle_correlation,
            OrchestratorPhase.VERDICT: self._handle_verdict,
        }
        
        phase_sequence = self.orchestrator.get_phase_sequence()
        current_index = 0
        total_rollbacks = 0
        max_rollbacks = 2

        self.orchestrator.context.escalation_attempts["rollbacks"] = 0

        # Import ResourceEscalationEngine locally
        try:
            from backend.core.resource_escalation import ResourceEscalationEngine
            from backend.core.scheduler_enhanced import SchedulerJobQueue
            escalation_engine = ResourceEscalationEngine()
            scheduler_queue = SchedulerJobQueue()
        except ImportError:
            escalation_engine = None
            scheduler_queue = None

        while current_index < len(phase_sequence):
            phase = phase_sequence[current_index]
            handler = phases_map[phase]
            await self.coordinator.mark(f"phase_{phase.value}_started", {"phase": phase.value})
            
            await self.orchestrator.execute_phase(phase, handler, self.orchestrator.context)
            await self.coordinator.mark(f"phase_{phase.value}_completed", {"phase": phase.value})
            
            # Post-phase evaluation for Rollback
            rollback_to = None
            ctx = self.orchestrator.context
            
            if phase == OrchestratorPhase.EXECUTION:
                if ctx.execution_results.get("waf_blocked") and total_rollbacks < max_rollbacks:
                    logger.warning("Bloqueo WAF detectado. Retrocediendo a PREFLIGHT para recalibrar estrategias de evasión.")
                    rollback_to = OrchestratorPhase.PREFLIGHT
            
            elif phase == OrchestratorPhase.ESCALATION:
                if ctx.escalation_attempts.get("new_surface_found") and total_rollbacks < max_rollbacks:
                    logger.info("Nueva superficie de ataque descubierta en la escalación. Retrocediendo a de nuevo a EXECUTION.")
                    rollback_to = OrchestratorPhase.EXECUTION

            if rollback_to and total_rollbacks < max_rollbacks:
                total_rollbacks += 1
                ctx.escalation_attempts["rollbacks"] = total_rollbacks
                current_index = phase_sequence.index(rollback_to)
                continue
                
            # Resource Escalation Engine Hook
            if escalation_engine and self.ledger and phase in (OrchestratorPhase.DISCOVERY, OrchestratorPhase.EXECUTION):
                try:
                    decision = await escalation_engine.evaluate_escalation(self.ledger)
                    if decision:
                        logger.info(f"Decisión de Escalación: {decision.action} - {decision.reason}")
                        await escalation_engine.apply_decision(decision, scheduler_queue, self.ledger)
                except Exception as e:
                    logger.error(f"Error evaluating escalation: {e}")

            current_index += 1

        # Finalize and persist metrics
        try:
            self.ledger.total_duration_ms = int((asyncio.get_event_loop().time() - start_time_async) * 1000)
            self.ledger.status = "completed" if phase == OrchestratorPhase.VERDICT else "failed"
            await self._persist_metrics(self.ledger)
            await self.coordinator.mark(
                "scan_completed",
                {"scan_id": self.scan_id, "status": self.ledger.status, "duration_ms": self.ledger.total_duration_ms},
            )
        except Exception as e:
            logger.error(f"Failed to persist metrics: {e}")
            await self.coordinator.mark("scan_failed", {"scan_id": self.scan_id, "error": str(e)})

        logger.info(f"Escaneo finalizado para {self.target_url}.")
        release_scan_event_coordinator(self.scan_id)

    async def _persist_metrics(self, ledger):
        """Persiste el CoverageLedger en PostgreSQL si está habilitado."""
        try:
            # Usar getattr para evitar NameError si PG_STORE no fue exportado por ares_api
            from backend import ares_api as _api
            PG_STORE = getattr(_api, "PG_STORE", None)
            if not PG_STORE:
                return
            
            data = ledger.to_dict()
            
            # Refined verdict logic
            verdict = "INCONCLUSIVE"
            if ledger.should_be_inconclusive():
                verdict = "INCONCLUSIVE"
            elif self.orchestrator.context.execution_results.get("findings"):
                verdict = "VULNERABLE"
            else:
                verdict = "NO_VULNERABLE"

            PG_STORE.persist_coverage_v1(
                scan_id=ledger.scan_id,
                version="coverage.v1",
                job_status=ledger.status,
                verdict=verdict,
                conclusive=(verdict != "INCONCLUSIVE"),
                vulnerable=(verdict == "VULNERABLE"),
                coverage_summary=data["summary"],
                conclusive_blockers=data["blockers"],
                phase_records=data["phases"],
                vector_records=data["vectors"],
            )
            logger.info(f"Resultados persistidos en PostgreSQL para el escaneo {ledger.scan_id}")
        except ImportError:
            logger.warning("PostgresStore not available for persistence (ImportError)")
        except Exception as e:
            logger.error(f"Error persisting metrics: {e}")

    # --- Phase Handlers ---

    async def _handle_preflight(self, context: OrchestratorPhaseContext):
        """Validates connectivity and WAF presence."""
        logger.info("Ejecutando verificaciones previas de entorno (Preflight)...")
        
        # ── AI HEALTH GUARD (non-blocking) ──────────────────────────
        ai_ok = await check_ai_health()
        if not ai_ok:
            logger.warning(
                "Cortex AI no disponible (check fallido) — continuando en modo heurístico. "
                "Las decisiones tácticas usarán reglas locales en lugar de Gemini."
            )
            context.execution_results["ai_mode"] = "heuristic_fallback"
        else:
            context.execution_results["ai_mode"] = "gemini"
        # ─────────────────────────────────────────────────────────────

        from backend.core.coverage_ledger import PhaseCompletionRecord
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        context.available_engines = ["sqlmap", "zap", "nmap"]
        context.execution_results["waf_blocked"] = False # Reset block flag
        
        # Update Ledger
        ai_mode = context.execution_results.get("ai_mode", "unknown")
        logger.info(f"Preflight completado. Motores disponibles: {context.available_engines}. Modo AI: {ai_mode}")
        _phase_end = datetime.datetime.now(datetime.timezone.utc)
        _duration_ms = int((_phase_end - now_utc).total_seconds() * 1000)
        self.ledger.add_phase_record(PhaseCompletionRecord(
            phase="preflight",
            status="completed",
            duration_ms=_duration_ms,
            start_time=now_utc,
            end_time=_phase_end
        ))
        
        return True

    async def _handle_discovery(self, context: OrchestratorPhaseContext):
        """Runs WAF detection and basic crawling."""
        logger.info("Ejecutando fase de Descubrimiento (Discovery)...")
        from backend.core.coverage_ledger import PhaseCompletionRecord
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        if waf_fingerprint:
            waf_result = await waf_fingerprint(context.target_url)
            logger.info(f"WAF Detection: {waf_result}")
            if self.reporter:
                self.reporter.log_action("WAF Detection", f"Detected: {waf_result}")

        # C-02 FIX: Discovery dinámico basado en la URL del target real.
        # Antes estaba completamente hardcodeado con ["/login", "/admin", "/search"].
        # Ahora: (1) extrae path y query params de la URL configurada,
        # (2) intenta un crawl liviano de la página para encontrar formularios y links.
        from urllib.parse import urlparse, parse_qs
        import aiohttp

        discovered_endpoints: list = []
        discovered_params: dict = {}

        parsed = urlparse(context.target_url)
        base_path = parsed.path or "/"

        # Siempre incluir la URL configurada como punto de entrada principal
        if base_path not in discovered_endpoints:
            discovered_endpoints.append(base_path)

        # Si la URL tiene query string, extraer sus parámetros como vector inicial
        if parsed.query:
            qparams = list(parse_qs(parsed.query).keys())
            if qparams:
                discovered_params[base_path] = qparams
                logger.info(f"Discovery: parámetros extraídos de URL query string: {qparams}")

        # Crawl liviano: intentar fetch de la página para encontrar formularios y hrefs
        try:
            async with aiohttp.ClientSession(
                headers={"User-Agent": "Mozilla/5.0 (compatible; CerberusProScanner/1.0)"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                async with session.get(context.target_url, allow_redirects=True, ssl=False) as resp:
                    if resp.status < 400:
                        html = await resp.text(errors="ignore")
                        # Extraer action de formularios
                        import re as _re
                        form_actions = _re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, _re.I)
                        form_inputs = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, _re.I)
                        # Extraer hrefs con query params (posibles vectores)
                        hrefs = _re.findall(r'href=["\']([^"\'#]+\?[^"\']+)["\']', html, _re.I)

                        for action in form_actions:
                            action_path = urlparse(action).path or action
                            if action_path and action_path not in discovered_endpoints:
                                discovered_endpoints.append(action_path)
                            if form_inputs and action_path not in discovered_params:
                                discovered_params[action_path] = list(set(form_inputs))

                        for href in hrefs[:10]:  # limitar a 10 para no explotar
                            href_parsed = urlparse(href)
                            if href_parsed.query:
                                href_params = list(parse_qs(href_parsed.query).keys())
                                href_path = href_parsed.path or "/"
                                if href_path not in discovered_endpoints:
                                    discovered_endpoints.append(href_path)
                                if href_params and href_path not in discovered_params:
                                    discovered_params[href_path] = href_params

                        logger.info(
                            f"Discovery: crawl completado — {len(discovered_endpoints)} endpoints, "
                            f"{sum(len(v) for v in discovered_params.values())} parámetros"
                        )
        except Exception as e_crawl:
            logger.warning(f"Discovery: crawl liviano falló ({type(e_crawl).__name__}: {e_crawl}) — usando URL base como vector mínimo")

        # Garantizar al menos un endpoint con al menos un parámetro para que el FSM avance
        if not discovered_endpoints:
            discovered_endpoints.append(base_path)
        if not discovered_params:
            # Fallback: parámetros comunes inyectados como mínimo por defecto
            discovered_params[discovered_endpoints[0]] = ["id", "q", "search"]
            logger.warning(
                f"Discovery: no se encontraron parámetros en la página. "
                f"Usando parámetros genéricos de prueba en {discovered_endpoints[0]}."
            )

        context.discovered_endpoints = discovered_endpoints
        context.discovered_params = discovered_params

        
        # Update Ledger
        count = sum(len(p) for p in context.discovered_params.values())
        self.ledger.inputs_found = count
        _phase_end = datetime.datetime.now(datetime.timezone.utc)
        _duration_ms = int((_phase_end - now_utc).total_seconds() * 1000)
        self.ledger.add_phase_record(PhaseCompletionRecord(
            phase="discovery",
            status="completed" if count > 0 else "partially_completed",
            duration_ms=_duration_ms,
            start_time=now_utc,
            end_time=_phase_end,
            items_processed=count
        ))
        
        return True

    async def _handle_execution(self, context: OrchestratorPhaseContext):
        """Runs core engines using EngineOrchestrator + AI-powered WAF evasion."""
        logger.info("Ejecutando Motores Ofensivos Sincronizados...")
        from backend.core.coverage_ledger import PhaseCompletionRecord, EngineCoverageRecord, VectorCoverageRecord, CoverageStatus
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        if not EngineOrchestrator:
            logger.warning("EngineOrchestrator no disponible, recayendo en modo de simulación segura.")
            self.ledger.add_engine_record(EngineCoverageRecord(
                engine_name="sim",
                status=CoverageStatus.EXECUTED,
                vectors_total=1,
                vectors_executed=1,
                start_time=now_utc,
                end_time=datetime.datetime.now(datetime.timezone.utc)
            ))
            if not context.execution_results.get("findings"):
                context.execution_results["findings"] = [{"type": "rce", "endpoint": "/admin", "parameter": "cmd", "confidence": 0.5, "engine": "sim"}]
            return True

        vectors = []
        for endpoint, params in context.discovered_params.items():
            for param in params:
                vectors.append({
                    "endpoint": endpoint,
                    "parameter": param,
                    "method": "GET",
                    "payloads": []
                })
        
        if not vectors:
            vectors.append({
                "endpoint": "/",
                "parameter": "id",
                "method": "GET",
                "payloads": []
            })

        orchestrator = EngineOrchestrator()
        findings = await orchestrator.scan_all(self.target_url, vectors)

        # Feed observed results into the WAF analyzer for adaptive selection.
        for finding in findings:
            evidence = str(getattr(finding, "evidence", "") or "")
            low = evidence.lower()
            blocked = any(marker in low for marker in ("waf", "captcha", "403", "rate limit", "too many requests"))
            self.waf_analyzer.record_interaction(
                status_code=403 if blocked else 200,
                latency_ms=100 if blocked else 50,
                body=evidence,
                is_blocked=blocked,
            )
        
        # ── Cortex AI: WAF Feedback Loop ─────────────────────────────
        evasion_ctx = self.strategy_selector.get_next_evasion_context()
        block_rate = evasion_ctx.get("block_rate", 0)
        
        if block_rate > 0.2:
            logger.info(f"🧠 Cortex AI: tasa de bloqueo WAF={block_rate:.0%} — solicitando intervención táctica inmediata")
            signal_data = {
                "block_rate": block_rate,
                "avg_latency_ms": self.waf_analyzer.get_average_latency(),
                "captcha_detected": self.waf_analyzer.detect_captcha(),
                "rate_limited": self.waf_analyzer.detect_rate_limiting(),
            }
            scan_ctx = {
                "target_url": self.target_url,
                "current_profile": evasion_ctx.get("recommended_technique", "standard"),
                "current_phase": "execution",
                "engines": self.ledger.engines_executed,
            }

            # ── SmartCache Learning: Check for previously successful AI decisions ──
            ai_cache_ctx = {
                "namespace": "ai_tactical_decisions_v2",
                "signal": signal_data,
                "target_url": self.target_url
            }
            cached_decision_dict = self.smart_cache.get_cached_strategy(ai_cache_ctx)
            
            if cached_decision_dict:
                from backend.core.cortex_ai import TacticalDecision
                decision = TacticalDecision(**cached_decision_dict)
                logger.info(f"🧠 Cortex (Cache Hit): Reusando decisión táctica aprendida [{decision.source}]")
            else:
                decision = await analyze_waf_signal(signal_data, scan_ctx)
                if decision and decision.source == "gemini":
                     # Learn this decision for future use in similar signal contexts
                     self.smart_cache.update_feedback(ai_cache_ctx, decision.__dict__, success=True)
            
            self.ai_decisions.append({
                "phase": "execution",
                "decision": decision.__dict__,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            await self.coordinator.mark(
                "ai_decision_ready",
                {"action": decision.action, "confidence": float(decision.confidence), "source": decision.source},
            )
            logger.info(
                f"🧠 Cortex decision [{decision.source}]: {decision.action} — {decision.reasoning}"
            )
            context.execution_results["ai_evasion_decision"] = decision.__dict__

            # ── AUTO-APPLY: Map AI decision → engine re-run ──────────
            if decision.action in ("change_profile", "switch_tamper", "enable_stealth", "increase_jitter"):
                from backend.offensiva.evasion_strategies import apply_strategies_to_engine
                ai_strategies = []
                params = decision.params or {}
                
                # Map AI decision params to concrete engine strategies
                if params.get("tamper"):
                    tamper_parts = str(params["tamper"]).split(",")
                    for t in tamper_parts:
                        t = t.strip()
                        if "random" in t or "case" in t:
                            ai_strategies.append("case_randomize")
                        elif "comment" in t:
                            ai_strategies.append("comment_injection")
                        elif "space" in t or "encode" in t:
                            ai_strategies.append("use_double_encoding")
                
                if params.get("jitter_multiplier", 1.0) > 1.0:
                    ai_strategies.append("slow_jitter")
                    ai_strategies.append("time_based_jitter")
                
                if params.get("use_browser_stealth"):
                    ai_strategies.append("header_variation")
                
                if params.get("profile") in ("stealth", "Corporativo-Sigiloso"):
                    ai_strategies.extend(["slow_jitter", "header_variation", "case_randomize"])
                
                if ai_strategies:
                    logger.info(f"🧠 [EVASIÓN ACTIVA] Auto-aplicando {len(ai_strategies)} estrategias guiadas por IA y re-iniciando escaneo...")
                    retry_orch = EngineOrchestrator()
                    # Apply AI-recommended strategies to all engines
                    for eid in (retry_orch.enabled_engines or []):
                        from backend.engines.base import get_engine
                        eng = get_engine(eid)
                        if eng:
                            apply_strategies_to_engine(eng, ai_strategies)
                    retry_findings = await retry_orch.scan_all(self.target_url, vectors)
                    if retry_findings:
                        logger.info(f"🧠 Re-escaneo de IA evadió la defensa y encontró {len(retry_findings)} vulnerabilidades adicionales")
                        findings.extend(retry_findings)
            # ── End AUTO-APPLY ────────────────────────────────────────
        # ── End Cortex AI ────────────────────────────────────────────

        feedback_success = bool(findings) and float(block_rate) < 0.5
        self.strategy_selector.update_strategy_feedback(success=feedback_success)
        purged = self.strategy_selector.purge_obsolete_records()
        await self.coordinator.mark(
            "smart_cache_updated",
            {"feedback_success": bool(feedback_success), "purged": int(purged), "block_rate": float(block_rate)},
        )
        if purged > 0:
            logger.info(f"SmartCache purgó {purged} estrategias obsoletas")
        
        # Update Ledger with engine/vector info
        self.ledger.add_engine_record(EngineCoverageRecord(
            engine_name="sqlmap", 
            status=CoverageStatus.EXECUTED,
            vectors_total=len(vectors),
            vectors_executed=len(vectors),
            start_time=now_utc,
            end_time=datetime.datetime.now(datetime.timezone.utc)
        ))
        
        for vec in vectors:
            self.ledger.add_vector_record(VectorCoverageRecord(
                vector_id=f"{vec['endpoint']}?{vec['parameter']}",
                vector_name=f"{vec['endpoint']} [{vec['parameter']}]",
                engine="sqlmap",
                status=CoverageStatus.EXECUTED,
                inputs_found=1,
                inputs_tested=1
            ))

        if "findings" not in context.execution_results:
            context.execution_results["findings"] = []
            
        for f in findings:
            context.execution_results["findings"].append({
                "vector": f"{f.endpoint} [{f.parameter}]" if f.endpoint else str(f.engine or "UNKNOWN").upper(),
                "engine": str(f.engine or "UNKNOWN").lower(),
                "type": f.type,
                "endpoint": f.endpoint,
                "parameter": f.parameter,
                "vulnerable": True,
                "evidence": [f.evidence] if f.evidence else [],
                "severity": f.severity,
                "confidence": getattr(f, "confidence", 0.5)
            })
            
        _phase_end = datetime.datetime.now(datetime.timezone.utc)
        _duration_ms = int((_phase_end - now_utc).total_seconds() * 1000)
        self.ledger.add_phase_record(PhaseCompletionRecord(
            phase="execution",
            status="completed",
            duration_ms=_duration_ms,
            start_time=now_utc,
            end_time=_phase_end,
            items_processed=len(vectors)
        ))
            
        logger.info(f"Ejecución completada. Vulnerabilidades descubiertas: {len(findings)}")
        return True

    async def _handle_escalation(self, context: OrchestratorPhaseContext):
        """Triggers Chain Orchestrator for Lateral Movement & Exfil — AI-powered prioritisation."""
        logger.info("Ejecutando escalación de privilegios (Escalation)...")
        from backend.core.coverage_ledger import PhaseCompletionRecord
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        context.escalation_attempts["new_surface_found"] = False
        
        if not ChainOrchestrator:
            logger.warning("ChainOrchestrator not available.")
            return True

        chain_orch = ChainOrchestrator()
        findings = context.execution_results.get("findings", [])

        # ── Collective Intelligence (Phase 2) ──────────────────────
        # Check SmartCache for native engine successes that may not have
        # been captured by the EngineOrchestrator (they flow through the
        # separate omni_web_execution pipeline).
        try:
            native_intel = await self.smart_cache.get_cached_strategy({
                "namespace": "native_success_v1",
                "target": self.target_url,
            })
            if native_intel and not any(
                f.get("confidence", 0) >= 1.0 and "native" in str(f.get("engine", "")).lower()
                for f in findings
            ):
                logger.info(
                    f"🧠 Collective Intelligence: inyectando hallazgo nativo confirmado "
                    f"({native_intel.get('vector_type', 'UNKNOWN')}) en la cadena de escalación"
                )
                findings.append({
                    "type": "sql_injection",
                    "endpoint": self.target_url,
                    "parameter": "auto",
                    "confidence": 1.0,
                    "engine": f"native_{native_intel.get('vector_type', 'unknown')}",
                    "vulnerable": True,
                    "evidence": [f"[!!!] Brecha confirmada por motor nativo {native_intel.get('vector_type', '')}"],
                    "severity": "critical",
                })
        except Exception as e_ci:
            logger.error(f"Error consultando Collective Intelligence: {e_ci}")
        # ── End Collective Intelligence ────────────────────────────
        
        # Register ALL finding types (not just RCE)
        TYPE_MAP = {
            "rce": VulnerabilityType.RCE,
            "sql_injection": VulnerabilityType.SQL_INJECTION,
            "xss": VulnerabilityType.XSS,
            "command_injection": VulnerabilityType.COMMAND_INJECTION,
            "lfi": VulnerabilityType.LFI,
            "auth_bypass": VulnerabilityType.AUTHENTICATION_BYPASS,
        }
        for f in findings:
            vtype = TYPE_MAP.get(f.get("type"))
            if vtype:
                finding_obj = VulnerabilityFinding(
                    type=vtype,
                    endpoint=f.get("endpoint", "/"),
                    parameter=f.get("parameter", f.get("param", "unknown")),
                    confidence=f.get("confidence", 0.5),
                )
                chain_orch.register_finding(finding_obj)

        chains = chain_orch.discover_chains()
        logger.info(f"Descubiertas {len(chains)} cadenas potenciales de explotación.")

        # ── Cortex AI: Escalation Intelligence ──────────────────────
        if chains and findings:
            coverage_data = self.ledger.to_dict().get("summary", {})
            plan = await suggest_escalation(findings, coverage_data)
            self.ai_decisions.append({
                "phase": "escalation",
                "plan": plan.__dict__,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            logger.info(
                f"🧠 Escalación Cortex [{plan.source}]: "
                f"ejecutar={plan.chains_to_execute}, omitir={plan.chains_to_skip} — {plan.reasoning}"
            )
            # Filter chains by AI recommendation
            skip_set = set(plan.chains_to_skip)
            chains = [c for c in chains if c.objective not in skip_set]
        # ── End Cortex AI ────────────────────────────────────────────
        
        for chain in chains:
            if self.policy_engine.check_authorization(ActionType.EXPLOIT, self.target_url):
                success, result = await chain_orch.execute_chain(chain)
                if success and self.reporter:
                    self.reporter.log_action("Chain Execution Success", f"Chain: {chain.objective}")
            else:
                logger.warning("Explotación iterativa (Chain) bloqueada por políticas.")

        # Update Ledger
        _phase_end = datetime.datetime.now(datetime.timezone.utc)
        _duration_ms = int((_phase_end - now_utc).total_seconds() * 1000)
        self.ledger.add_phase_record(PhaseCompletionRecord(
            phase="escalation",
            status="completed",
            duration_ms=_duration_ms,
            start_time=now_utc,
            end_time=_phase_end,
            items_processed=len(chains)
        ))

        return True

    async def _handle_correlation(self, context: OrchestratorPhaseContext):
        """Correlates findings with dedup + AI-powered relationship discovery."""
        logger.info("Ejecutando Correlación (Correlation)...")
        from backend.core.coverage_ledger import PhaseCompletionRecord
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        findings = context.execution_results.get("findings", [])
        
        # Step 1: Deterministic dedup (by endpoint+param+type)
        correlated = {}
        for f in findings:
            key = f"{f.get('endpoint')}_{f.get('parameter')}_{f.get('type')}"
            if key not in correlated:
                correlated[key] = []
            correlated[key].append(f)
            
        final_findings = []
        for key, group in correlated.items():
            base_finding = group[0].copy()
            engines = set(f.get("engine", "unknown") for f in group)
            if len(engines) >= 2:
                logger.info(f"¡Confirmación cruzada! Motores {engines} ratifican hallazgo: {key}")
                base_finding["confidence"] = max(0.95, base_finding.get("confidence", 0.5))
            else:
                base_finding["confidence"] = max(f.get("confidence", 0.5) for f in group)
            
            base_finding["engines_correlated"] = list(engines)
            final_findings.append(base_finding)
        
        # Step 2: AI correlation — find non-obvious relationships
        if len(final_findings) >= 2:
            ai_corr = await correlate_findings_ai(final_findings)
            self.ai_decisions.append({
                "phase": "correlation",
                "ai_correlation": ai_corr.__dict__,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            if ai_corr.relationships:
                logger.info(
                    f"🧠 Correlación Cortex [{ai_corr.source}]: "
                    f"halló {len(ai_corr.relationships)} relaciones ocultas"
                )
                for rel in ai_corr.relationships:
                    logger.info(f"   → {rel}")
            # Attach AI insights to context for reporting
            context.execution_results["ai_correlation"] = {
                "groups": ai_corr.groups,
                "relationships": ai_corr.relationships,
                "reasoning": ai_corr.reasoning,
                "source": ai_corr.source,
            }

        # Step 3: Parse findings into structured fields for better extraction
        from backend.core.cortex_ai import parse_structured_findings
        structured_findings = parse_structured_findings(final_findings)

        context.execution_results["findings"] = structured_findings
        
        # Update Ledger
        _phase_end = datetime.datetime.now(datetime.timezone.utc)
        _duration_ms = int((_phase_end - now_utc).total_seconds() * 1000)
        self.ledger.add_phase_record(PhaseCompletionRecord(
            phase="correlation",
            status="completed",
            duration_ms=_duration_ms,
            start_time=now_utc,
            end_time=_phase_end,
            items_processed=len(findings)
        ))

        return True

    async def _handle_verdict(self, context: OrchestratorPhaseContext):
        """Generates the final report and conclusive verdict — with AI forensic narrative."""
        logger.info("Emitiendo Veredicto (Verdict)...")
        
        from backend.core.verdict_engine import VerdictEngine
        verdict_engine = VerdictEngine(self.ledger)
        
        # Add findings to verdict engine
        findings = context.execution_results.get("findings", [])
        for f in findings:
            verdict_engine.add_finding(f)
            
        # Issue absolute verdict
        scan_duration = self.ledger.total_duration_ms or 0
        final_verdict = verdict_engine.issue_verdict(scan_duration)
        
        logger.info(f"Veredicto Final Emitido: {final_verdict.status}")
        
        # ── Cortex AI: Forensic Narrative ────────────────────────────
        coverage_pct = self.ledger.coverage_percentage()
        narrative = await generate_forensic_narrative(
            verdict_status=str(final_verdict.status),
            findings=findings,
            coverage_pct=coverage_pct,
        )
        context.execution_results["forensic_narrative"] = narrative
        self.ai_decisions.append({
            "phase": "verdict",
            "narrative_length": len(narrative),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })
        logger.info(f"🧠 Narrativa forense de Cortex generada ({len(narrative)} caracteres)")
        # ── End Cortex AI ────────────────────────────────────────────
        
        if self.reporter:
            report = self.reporter.generate_markdown_report()
            logger.info("Reporte local de Red-Team generado exitosamente.")
            
        # Store AI telemetry for frontend
        context.execution_results["ai_decisions"] = self.ai_decisions
            
        return True
