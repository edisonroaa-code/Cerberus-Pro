"""
Unified multilevel job runtime extracted from ares_api.py.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from backend.core.waf_feedback_loop import WAFResponseAnalyzer, AdaptiveStrategySelector
from backend.core.smart_cache import get_shared_smart_cache
from backend.core.events import get_scan_event_coordinator, release_scan_event_coordinator
from backend.core.cortex_ai import (
    analyze_waf_signal, suggest_escalation,
    correlate_findings_ai, generate_forensic_narrative,
    parse_structured_findings,
)


@dataclass
class UnifiedMultilevelJobDeps:
    state: Any
    logger: Any
    canonical_job_kind: str
    normalize_job_kind_fn: Callable[[Any], str]
    normalize_unified_job_cfg_fn: Callable[[str, dict], dict]
    apply_autopilot_policy_fn: Callable[[dict, str, int], dict]
    validate_unified_target_policy_fn: Callable[[str, dict, str], None]
    read_unified_runtime_cfg_fn: Callable[[dict], dict]
    run_omni_surface_scan_fn: Callable[[str, dict], Awaitable[dict]]
    get_policy_engine_fn: Callable[[], Any]
    action_type: Any
    orchestrator_cls: Any
    orchestrator_phase: Any
    broadcast_log_fn: Callable[[str, str, str, Optional[dict]], Awaitable[Any]]
    job_update_fn: Callable[..., Awaitable[None]]
    job_now_fn: Callable[[], str]
    job_get_fn: Callable[[str], Awaitable[Optional[dict]]]
    history_dir: str


def _map_vector_to_vuln(vector_name: str, vuln_type_enum: Any):
    v = str(vector_name or "").upper()
    if v in {"UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "INLINE", "AIIE", "ENGINE_SQLMAP"}:
        return vuln_type_enum.SQL_INJECTION
    if "SSTI" in v:
        return vuln_type_enum.COMMAND_INJECTION
    if "NOSQL" in v:
        return vuln_type_enum.SECURITY_MISCONFIGURATION
    if v in {"WEBSOCKET", "MQTT", "GRPC"}:
        return vuln_type_enum.SECURITY_MISCONFIGURATION
    return vuln_type_enum.SECURITY_MISCONFIGURATION


async def run_unified_multilevel_job(
    scan_id: str,
    user_id: str,
    kind: str,
    cfg: dict,
    deps: UnifiedMultilevelJobDeps,
) -> None:
    source_kind = str(kind or "").strip().lower()
    kind_norm = deps.normalize_job_kind_fn(kind)
    if kind_norm != deps.canonical_job_kind:
        await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=f"unknown job kind: {kind}")
        return

    normalized_cfg = deps.normalize_unified_job_cfg_fn(source_kind, cfg)
    mode = str(normalized_cfg.get("mode") or "web").lower()

    if normalized_cfg.get("autoPilot"):
        normalized_cfg = deps.apply_autopilot_policy_fn(
            normalized_cfg,
            mode=mode,
            phase=int(normalized_cfg.get("autoPilotPhase") or 1),
        )

    await deps.job_update_fn(scan_id, config_json=json.dumps(normalized_cfg, ensure_ascii=False, sort_keys=True))

    try:
        deps.validate_unified_target_policy_fn(mode, normalized_cfg, user_id)
    except Exception as exc:
        await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=str(exc))
        return

    target_ref = str(normalized_cfg.get("url") or mode or "unknown")

    # ── AI Sovereign Configuration ──────────────────────────────
    # Ignore unsafe or suboptimal UI configs. The AI will dictate the baseline.
    try:
        from backend.core.cortex_ai import generate_initial_tactics
        tactics = await generate_initial_tactics(target_ref, mode, normalized_cfg)
        
        # Override UI configuration with AI tactical setup
        normalized_cfg["level"] = tactics.level
        normalized_cfg["risk"] = tactics.risk
        normalized_cfg["threads"] = tactics.threads
        normalized_cfg["tamper"] = tactics.tamper
        normalized_cfg["delay"] = max(int(normalized_cfg.get("delay", 0)), tactics.delay)
        
        # Log the AI takeover
        msg = f"Dictamen inicial: Level {tactics.level}, Risk {tactics.risk}, Threads {tactics.threads}, Tampers: {tactics.tamper} ({tactics.reasoning})"
        await deps.broadcast_log_fn("🧠 CORTEX", "INFO", f"Tomando control soberano de la configuración. {msg}")
        deps.logger.info(f"🧠 Sovereign AI Setup: {msg}")
    except Exception as e:
        deps.logger.error(f"Failed to apply AI sovereign configuration: {e}")
    # ────────────────────────────────────────────────────────────

    deps.state.omni_meta[user_id] = dict(deps.state.omni_meta.get(user_id) or {})
    deps.state.omni_meta[user_id]["scan_id"] = scan_id
    deps.state.omni_meta[user_id]["job_kind"] = kind_norm
    deps.state.omni_meta[user_id]["orchestrator"] = "unified_multilevel_v1"

    orchestrator = deps.orchestrator_cls(scan_id=scan_id, target_url=target_ref)
    coordinator = get_scan_event_coordinator(scan_id)
    await coordinator.mark(
        "job_started",
        {"kind": kind_norm, "mode": mode, "target": target_ref},
    )
    execution_payload: Dict[str, Any] = {}
    escalation_summary: Dict[str, Any] = {}
    ai_decisions: List[Dict[str, Any]] = []

    # WAF feedback loop + Cortex AI telemetry
    waf_analyzer = WAFResponseAnalyzer(window_size=30)
    cache_db_path = os.environ.get("CERBERUS_SMART_CACHE_DB", "backend/data/smart_cache.sqlite3")
    smart_cache = get_shared_smart_cache(db_path=cache_db_path)
    strategy_selector = AdaptiveStrategySelector(waf_analyzer, smart_cache=smart_cache)
    strategy_selector.set_runtime_context(target_ref=target_ref, mode=mode, orchestrator="unified_multilevel_job")

    async def _phase_preflight(_):
        return True

    async def _phase_discovery(_):
        return True

    async def _phase_execution(_):
        nonlocal execution_payload
        
        # Initial scan run
        phase_cfg = dict(normalized_cfg or {})
        phase_cfg["_defer_terminal_finalize"] = True
        execution_payload = (await deps.run_omni_surface_scan_fn(user_id, phase_cfg)) or {}
        await coordinator.mark(
            "vectors_completed",
            {
                "results_count": len(execution_payload.get("data", []) if isinstance(execution_payload, dict) else []),
            },
        )
        
        # ── Cortex AI: Tactical Adaptation Loop ────────────────────────
        # Allows the AI to "order" a reconfiguration if the first pass is blocked or ineffective
        max_tactical_retries = 1
        for attempt in range(max_tactical_retries):
            findings = execution_payload.get("data", []) if isinstance(execution_payload, dict) else []
            
            # Feed results to WAF analyzer
            for f in findings:
                if not isinstance(f, dict): continue
                evidence = f.get("evidence", [])
                has_block = any(any(k in str(line).lower() for k in ("captcha", "waf", "too many requests", "403")) for line in evidence)
                if has_block:
                    waf_analyzer.record_interaction(status_code=403, latency_ms=100, is_blocked=True)
                else:
                    waf_analyzer.record_interaction(status_code=200, latency_ms=50, is_blocked=False)

            evasion_ctx = strategy_selector.get_next_evasion_context()
            block_rate = evasion_ctx.get("block_rate", 0)
            
            # Determine if AI should intervene
            is_empty_or_inconclusive = len(findings) == 0
            is_strict = normalized_cfg.get("autoPilot") or execution_payload.get("strict_conclusive") or True # Always trigger if empty
            
            should_intervene = block_rate > 0.15 or (is_empty_or_inconclusive and is_strict)
            
            if should_intervene:
                deps.logger.info(f"🧠 Cortex AI: Analizando efectividad táctica (bloqueo={block_rate:.0%}, hallazgos={len(findings)})")
                signal_data = {
                    "block_rate": block_rate,
                    "avg_latency_ms": waf_analyzer.get_average_latency(),
                    "captcha_detected": waf_analyzer.detect_captcha(),
                    "rate_limited": waf_analyzer.detect_rate_limiting(),
                    "empty_results": len(findings) == 0,
                    "attempt": attempt + 1
                }
                scan_ctx = {
                    "target_url": target_ref,
                    "current_profile": normalized_cfg.get("profile", "standard"),
                    "current_phase": "execution",
                }
                
                decision = await analyze_waf_signal(signal_data, scan_ctx)
                ai_decisions.append({
                    "phase": "execution",
                    "attempt": attempt + 1,
                    "decision": decision.__dict__,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                await coordinator.mark(
                    "ai_decision_ready",
                    {
                        "action": decision.action,
                        "confidence": float(decision.confidence),
                        "attempt": attempt + 1,
                    },
                )
                
                if decision.action != "retry" and decision.confidence > 0.6:
                    deps.logger.info(f"🧠 ORDEN DE IA RECIBIDA: {decision.action.upper()} - {decision.reasoning}")
                    await deps.broadcast_log_fn("🧠 CORTEX", "INFO", f"Ordenando cambio táctico: {decision.action} ({decision.reasoning})")
                    
                    # Apply AI orders to configuration
                    if decision.action == "change_profile":
                        normalized_cfg["profile"] = decision.params.get("profile", "stealth")
                    elif decision.action == "switch_tamper":
                        normalized_cfg["tamper"] = decision.params.get("tamper", "randomcase,space2comment")
                    elif decision.action == "increase_jitter":
                        normalized_cfg["delay"] = int(normalized_cfg.get("delay", 0)) + 2
                    elif decision.action == "enable_stealth":
                        normalized_cfg["stealth"] = True
                    elif decision.action == "force_oob":
                        normalized_cfg["oob"] = True
                    
                    # Log mutation
                    deps.logger.info(f"🧠 Mutación aplicada por IA. Re-ejecutando con órdenes nuevas...")
                    retry_cfg = dict(normalized_cfg or {})
                    retry_cfg["_defer_terminal_finalize"] = True
                    execution_payload = (await deps.run_omni_surface_scan_fn(user_id, retry_cfg)) or {}
                    # Continue loop to see if 2nd pass worked
                else:
                    deps.logger.info(f"🧠 Cortex AI: Manteniendo táctica actual ({decision.reasoning})")
                    break # AI says continue as is
            else:
                break # Not blocked, no need for AI intervention
                
        # ── End Cortex AI ────────────────────────────────────────────
        final_findings = execution_payload.get("data", []) if isinstance(execution_payload, dict) else []
        final_block_rate = waf_analyzer.get_block_rate()
        feedback_success = isinstance(final_findings, list) and len(final_findings) > 0 and final_block_rate < 0.5
        strategy_selector.update_strategy_feedback(success=feedback_success)
        purged = strategy_selector.purge_obsolete_records()
        await coordinator.mark(
            "smart_cache_updated",
            {
                "success_feedback": bool(feedback_success),
                "purged": int(purged),
                "block_rate": float(final_block_rate),
            },
        )
        if purged > 0:
            deps.logger.info(f"SmartCache purgó {purged} estrategias obsoletas")
        return True

    async def _phase_escalation(_):
        nonlocal escalation_summary
        escalation_cfg = dict((deps.read_unified_runtime_cfg_fn(normalized_cfg).get("escalation", {}) or {}))
        execute_requested = bool(escalation_cfg.get("execute", False))
        policy = deps.get_policy_engine_fn()
        allow_exploit = bool(policy.check_authorization(deps.action_type.EXPLOIT, target_ref))
        allow_lateral = bool(policy.check_authorization(deps.action_type.LATERAL_MOVE, target_ref))
        allow_exfil = bool(policy.check_authorization(deps.action_type.EXFILTRATE, target_ref))

        escalation_summary = {
            "status": "skipped",
            "execute_requested": execute_requested,
            "allow_active_chain": bool(escalation_cfg.get("allow_active_chain", False)),
            "policy": {
                "exploit": allow_exploit,
                "lateral_movement": allow_lateral,
                "exfiltrate": allow_exfil,
            },
            "findings_considered": 0,
            "chains_discovered": 0,
            "chains_preview": [],
        }

        if not any([allow_exploit, allow_lateral, allow_exfil]):
            escalation_summary["status"] = "blocked_by_policy"
            deps.state.omni_meta[user_id]["escalation"] = escalation_summary
            await deps.broadcast_log_fn("ORQUESTADOR", "WARNING", "Escalation bloqueada por gobernanza")
            return True

        results_data = execution_payload.get("data") if isinstance(execution_payload, dict) else None
        if not isinstance(results_data, list):
            escalation_summary["status"] = "no_execution_data"
            deps.state.omni_meta[user_id]["escalation"] = escalation_summary
            return True

        try:
            from core.chain_orchestrator import ChainOrchestrator, VulnerabilityFinding, VulnerabilityType
        except Exception as exc:
            escalation_summary["status"] = f"chain_unavailable:{type(exc).__name__}"
            deps.state.omni_meta[user_id]["escalation"] = escalation_summary
            await deps.broadcast_log_fn("ORQUESTADOR", "WARNING", "Chain orchestrator no disponible")
            return True

        chain_orch = ChainOrchestrator()
        findings_added = 0
        findings_added_objs = []
        for item in results_data:
            if not isinstance(item, dict):
                continue
            if not bool(item.get("vulnerable")):
                continue
            vector_name = str(item.get("vector") or "UNKNOWN")
            vuln_type = _map_vector_to_vuln(vector_name, VulnerabilityType)
            evidence_list = item.get("evidence") if isinstance(item.get("evidence"), list) else []
            finding = VulnerabilityFinding(
                type=vuln_type,
                endpoint=target_ref,
                parameter=str(item.get("parameter") or "auto"),
                confidence=0.8,
                payload=str(item.get("command") or ""),
                response_evidence=str(evidence_list[0]) if evidence_list else None,
                severity="high",
            )
            chain_orch.register_finding(finding)
            findings_added_objs.append({
                "type": str(item.get("type", "unknown")),
                "endpoint": target_ref,
                "parameter": str(item.get("parameter", "auto")),
                "severity": "high"
            })
            findings_added += 1

        escalation_summary["findings_considered"] = findings_added
        if findings_added == 0:
            escalation_summary["status"] = "no_confirmed_findings"
            deps.state.omni_meta[user_id]["escalation"] = escalation_summary
            return True

        chains = chain_orch.discover_chains()
        
        # ── Cortex AI: Escalation Intelligence ──────────────────────
        if chains and findings_added > 0:
            plan = await suggest_escalation(findings_added_objs, {"coverage_percentage": 0}) # Simplified coverage
            ai_decisions.append({
                "phase": "escalation",
                "plan": plan.__dict__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            deps.logger.info(
                f"🧠 Escalación Cortex [{plan.source}]: "
                f"ejecutar={plan.chains_to_execute}, omitir={plan.chains_to_skip} — {plan.reasoning}"
            )
            # Filter chains by AI recommendation if needed
        # ── End Cortex AI ────────────────────────────────────────────

        escalation_summary["chains_discovered"] = len(chains)
        escalation_summary["chains_preview"] = [
            {
                "chain_id": c.chain_id,
                "objective": c.objective,
                "confidence": float(c.total_confidence),
                "steps": int(len(c.chain_links)),
            }
            for c in chains[:10]
        ]

        if execute_requested:
            allow_active_chain = bool(escalation_cfg.get("allow_active_chain", False))
            try:
                max_chain_conf = max((float(getattr(c, "total_confidence", 0.0) or 0.0) for c in chains), default=0.0)
            except Exception:
                max_chain_conf = 0.0

            user_meta = deps.state.omni_meta.get(user_id, {})
            failures = int(user_meta.get("active_extraction_failures", 0))
            if failures >= 3:
                escalation_summary["status"] = "blocked_circuit_breaker"
                escalation_summary["note"] = "active_extraction_blocked_after_repeated_defenses"
                deps.state.omni_meta.setdefault(user_id, {}).update({"escalation": escalation_summary})
                await deps.broadcast_log_fn(
                    "ORQUESTADOR",
                    "WARN",
                    "Circuit breaker: active extraction blocked due to repeated defenses",
                )
                return True

            execution_permitted = (allow_active_chain and allow_exploit) or (allow_exploit and (max_chain_conf >= 0.8))
            if execution_permitted:
                sql_vectors = {"UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "INLINE", "AIIE_SQLI", "ENGINE_SQLMAP"}
                base_sqlmap_cmd: Optional[List[str]] = None
                for item in results_data:
                    if not isinstance(item, dict):
                        continue
                    if not bool(item.get("vulnerable")):
                        continue
                    if str(item.get("vector") or "").upper() not in sql_vectors:
                        continue
                    cmd = item.get("command")
                    if not isinstance(cmd, list) or not cmd:
                        continue
                    if not any("sqlmap" in str(c).lower() for c in cmd):
                        continue
                    base_sqlmap_cmd = [str(c) for c in cmd]
                    break

                if not base_sqlmap_cmd:
                    escalation_summary["status"] = "planned_only"
                    escalation_summary["note"] = "no_sqlmap_base_command_for_active_chain"
                    await deps.broadcast_log_fn(
                        "ORQUESTADOR",
                        "WARNING",
                        "Escalation activa solicitada, pero no hay comando base SQLMap utilizable",
                    )
                else:
                    deps.state.omni_meta.setdefault(user_id, {})
                    deps.state.omni_meta[user_id]["active_extraction_attempts"] = (
                        int(deps.state.omni_meta[user_id].get("active_extraction_attempts", 0)) + 1
                    )
                    try:
                        from post_exploitation import PostExploitationEngine

                        post_cfg: Dict[str, Any] = {
                            "extract_data": bool(escalation_cfg.get("extract_data", True)),
                            "file_read": bool(escalation_cfg.get("file_read", False)),
                            "attempt_shell": False,
                            "sandbox_execution": bool(escalation_cfg.get("sandbox_execution", True)),
                            "dump_limit": int(escalation_cfg.get("dump_limit", 10)),
                        }
                        if not allow_exfil:
                            post_cfg["extract_data"] = False
                            post_cfg["file_read"] = False

                        await deps.broadcast_log_fn(
                            "ORQUESTADOR",
                            "INFO",
                            "Escalation activa: ejecutando cadena post-explotacion controlada",
                            {"sandbox": post_cfg["sandbox_execution"], "extract_data": post_cfg["extract_data"]},
                        )
                        post_engine = PostExploitationEngine(
                            base_cmd=base_sqlmap_cmd,
                            scan_id=scan_id,
                            broadcast_fn=deps.broadcast_log_fn,
                            config=post_cfg,
                        )
                        chain_results = await post_engine.run_chain(post_cfg)
                        escalation_summary["status"] = "active_executed"
                        escalation_summary["active_chain_results"] = len(chain_results or [])
                        if isinstance(execution_payload.get("data"), list) and chain_results:
                            execution_payload["data"].extend(chain_results)

                        detected_defense = False
                        try:
                            for cr in (chain_results or []):
                                if isinstance(cr, dict):
                                    ev = cr.get("evidence") or []
                                    if isinstance(ev, list):
                                        for line in ev:
                                            if isinstance(line, str) and (
                                                "runtime_signal:waf" in line
                                                or "runtime_signal:captcha" in line
                                                or "runtime_signal:rate_limit" in line
                                            ):
                                                detected_defense = True
                                                break
                                elif isinstance(cr, str) and any(
                                    k in cr.lower() for k in ("captcha", "waf", "too many requests", "403", "502")
                                ):
                                    detected_defense = True
                                    break
                        except Exception:
                            detected_defense = False

                        if detected_defense:
                            deps.state.omni_meta[user_id]["active_extraction_failures"] = (
                                int(deps.state.omni_meta[user_id].get("active_extraction_failures", 0)) + 1
                            )
                            await deps.broadcast_log_fn(
                                "ORQUESTADOR",
                                "WARN",
                                "Defensive signals detected during active extraction; incrementing failure counter",
                            )
                            if int(deps.state.omni_meta[user_id]["active_extraction_failures"]) >= 3:
                                deps.state.omni_meta[user_id]["escalation_blocked"] = True
                                escalation_summary["status"] = "blocked_after_repeated_defenses"
                                escalation_summary["note"] = "reverted_to_plan_only_due_to_repeated_waf_detection"
                        else:
                            deps.state.omni_meta[user_id]["active_extraction_failures"] = 0

                    except Exception as exc:
                        escalation_summary["status"] = f"active_chain_error:{type(exc).__name__}"
                        escalation_summary["note"] = str(exc)
                        await deps.broadcast_log_fn(
                            "ORQUESTADOR",
                            "ERROR",
                            f"Escalation activa fallo: {type(exc).__name__}: {exc}",
                        )
            else:
                escalation_summary["status"] = "planned_only"
                escalation_summary["note"] = "active_chain_disabled_or_not_authorized_or_low_confidence"
                await deps.broadcast_log_fn(
                    "ORQUESTADOR",
                    "INFO",
                    "Escalation: cadenas descubiertas y planificadas (sin ejecucion activa)",
                )
        else:
            escalation_summary["status"] = "discovered"
            await deps.broadcast_log_fn("ORQUESTADOR", "INFO", f"Escalation: {len(chains)} cadenas potenciales detectadas")

        deps.state.omni_meta[user_id]["escalation"] = escalation_summary
        return True

    async def _phase_correlation(_):
        findings = execution_payload.get("data", []) if isinstance(execution_payload, dict) else []
        if len(findings) >= 2:
            ai_corr = await correlate_findings_ai(findings)
            ai_decisions.append({
                "phase": "correlation",
                "ai_correlation": ai_corr.__dict__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            if ai_corr.relationships:
                deps.logger.info(f"🧠 Correlación Cortex [{ai_corr.source}]: halló {len(ai_corr.relationships)} relaciones")
        return True

    async def _phase_verdict(_):
        findings = execution_payload.get("data", []) if isinstance(execution_payload, dict) else []
        narrative = await generate_forensic_narrative(
            verdict_status="VULNERABLE" if any(f.get("vulnerable") for f in findings) else "NO_VULNERABLE",
            findings=findings,
            coverage_pct=0,
        )
        orchestrator.context.execution_results["forensic_narrative"] = narrative
        ai_decisions.append({
            "phase": "verdict",
            "narrative_length": len(narrative),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        deps.logger.info(f"🧠 Narrativa forense de Cortex generada")
        return True

    try:
        await orchestrator.execute_phase(deps.orchestrator_phase.PREFLIGHT, _phase_preflight, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.DISCOVERY, _phase_discovery, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.EXECUTION, _phase_execution, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.ESCALATION, _phase_escalation, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.CORRELATION, _phase_correlation, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.VERDICT, _phase_verdict, orchestrator.context)
        await coordinator.mark("verdict_completed", {"scan_id": scan_id})

        job = await deps.job_get_fn(scan_id) or {}
        if job.get("status") == "running":
            try:
                findings = execution_payload.get("data", []) if isinstance(execution_payload, dict) else []
                is_vulnerable = any(f.get("vulnerable") for f in findings if isinstance(f, dict))
                verdict = "VULNERABLE" if is_vulnerable else "NO_VULNERABLE"

                # G-01: Privacy Guard - Anonimizar información del operador
                final_history_cfg = dict(normalized_cfg or {})
                if "user_id" in final_history_cfg:
                    final_history_cfg["user_id"] = "[ANONYMIZED_OPERATOR]"
                
                history_data = {
                    "scan_id": scan_id,
                    "target": target_ref,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "config": final_history_cfg,
                    "verdict": verdict,
                    "message": "Escaneo Unificado Omnisurface completado (V4).",
                    "data": findings,
                    "evidenceCount": sum(1 for item in findings if isinstance(item, dict) and item.get("vulnerable")),
                    "resultsCount": len(findings),
                    "conclusive": True,
                    "mode": mode,
                    "kind": kind_norm,
                    "ai_decisions": ai_decisions,
                    "forensic_narrative": orchestrator.context.execution_results.get("forensic_narrative", ""),
                }

                secure_target = target_ref.replace("://", "_").translate(str.maketrans('\\/?*|"<>:', "_________"))
                filename = f"omni_{secure_target}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
                filepath = os.path.join(deps.history_dir, filename)

                if is_vulnerable:
                    # ── Fase 16: Automated Extraction & Loot Board ──

                    try:

                        from backend.ares_runtime import LOOT_DIR

                        if not os.path.exists(LOOT_DIR):

                            os.makedirs(LOOT_DIR, exist_ok=True)

                            

                        # Search for real data exfiltrated by engines (specifically AIIE or raw strings)

                        all_loot_fragments = []

                        for f in findings:

                            if isinstance(f, dict):

                                if f.get("loot"):

                                    all_loot_fragments.append(f["loot"])

                                elif f.get("evidence"):

                                    ev = f.get("evidence")

                                    if isinstance(ev, list):

                                        extracted = [str(x) for x in ev if "retrieved:" in str(x).lower()]

                                        if extracted:

                                            all_loot_fragments.append({"raw_extraction": extracted})

                        

                        if all_loot_fragments:

                            deps.logger.info(f"[*] Post-Exploitation AI: Persistiendo datos exfiltrados...")

                            

                            first_vector = findings[0].get("vector", "UNKNOWN") if findings and isinstance(findings[0], dict) else "UNKNOWN"

                            final_loot_data = {

                                "scan_id": scan_id,

                                "target": target_ref,

                                "timestamp": datetime.now(timezone.utc).isoformat(),

                                "technique_used": first_vector,

                                "extracted_data": {}

                            }

                            

                            for fragment in all_loot_fragments:

                                if isinstance(fragment, dict):

                                    final_loot_data["extracted_data"].update(fragment)

                                elif isinstance(fragment, list):

                                    final_loot_data["extracted_data"].setdefault("raw", []).extend(fragment)

                            

                            loot_filename = f"loot_{secure_target}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

                            loot_filepath = os.path.join(LOOT_DIR, loot_filename)

                            

                            with open(loot_filepath, "w", encoding="utf-8") as f:

                                json.dump(final_loot_data, f, indent=4, ensure_ascii=False)

                                

                            deps.logger.info(f"[+] Loot real almacenado exitosamente en: {loot_filename}")

                            await deps.broadcast_log_fn("ORQUESTADOR", "SUCCESS", f"Exfiltracion finalizada en: {loot_filename}", {"loot_file": loot_filename})

                        else:

                            deps.logger.info("[!] No se detectaron fragmentos de loot para persistir.")

                            

                    except Exception as loot_e:

                        deps.logger.error(f"Fallo en la persistencia de Loot Real: {loot_e}")

                    # ────────────────────────────────────────────────

                os.makedirs(deps.history_dir, exist_ok=True)
                with open(filepath, "w", encoding="utf-8") as history_file:
                    json.dump(history_data, history_file, ensure_ascii=False, indent=2)
                await coordinator.mark(
                    "report_persisted",
                    {
                        "filename": filename,
                        "findings": len(findings),
                        "verdict": verdict,
                    },
                )
                await deps.broadcast_log_fn(
                    "ORQUESTADOR",
                    "SUCCESS",
                    f"Reporte final sincronizado: {filename}",
                    {"scan_id": scan_id, "verdict": verdict},
                )
                
                await deps.job_update_fn(
                    scan_id,
                    status="completed",
                    finished_at=deps.job_now_fn(),
                    result_filename=filename,
                    vulnerable=1 if is_vulnerable else 0,
                )
                await coordinator.mark(
                    "scan_completed",
                    {"verdict": verdict, "result_filename": filename},
                )
                deps.logger.info(f"Historial JSON unificado generado exitosamente: {filename}")
            except Exception as hist_e:
                deps.logger.error(f"Error generando historial JSON para frontend: {hist_e}")
                await deps.job_update_fn(scan_id, status="completed", finished_at=deps.job_now_fn())
    except asyncio.CancelledError:
        await coordinator.mark("scan_cancelled", {"reason": "stopped_by_user"})
        await deps.job_update_fn(scan_id, status="stopped", finished_at=deps.job_now_fn(), error="stopped_by_user")
        raise
    except Exception as exc:
        await coordinator.mark("scan_failed", {"error": str(exc)})
        await deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=str(exc))
    finally:
        deps.state.omni_meta.pop(user_id, None)
        release_scan_event_coordinator(scan_id)
