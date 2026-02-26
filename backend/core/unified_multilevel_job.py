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
    job_update_fn: Callable[..., None]
    job_now_fn: Callable[[], str]
    job_get_fn: Callable[[str], Optional[dict]]
    history_dir: str


def _map_vector_to_vuln(vector_name: str, vuln_type_enum: Any):
    v = str(vector_name or "").upper()
    if v in {"UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "INLINE", "AIIE_SQLI", "ENGINE_SQLMAP"}:
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
        deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=f"unknown job kind: {kind}")
        return

    normalized_cfg = deps.normalize_unified_job_cfg_fn(source_kind, cfg)
    mode = str(normalized_cfg.get("mode") or "web").lower()

    if normalized_cfg.get("autoPilot"):
        normalized_cfg = deps.apply_autopilot_policy_fn(
            normalized_cfg,
            mode=mode,
            phase=int(normalized_cfg.get("autoPilotPhase") or 1),
        )

    deps.job_update_fn(scan_id, config_json=json.dumps(normalized_cfg, ensure_ascii=False, sort_keys=True))

    try:
        deps.validate_unified_target_policy_fn(mode, normalized_cfg, user_id)
    except Exception as exc:
        deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=str(exc))
        return

    deps.state.omni_meta[user_id] = dict(deps.state.omni_meta.get(user_id) or {})
    deps.state.omni_meta[user_id]["scan_id"] = scan_id
    deps.state.omni_meta[user_id]["job_kind"] = kind_norm
    deps.state.omni_meta[user_id]["orchestrator"] = "unified_multilevel_v1"

    target_ref = str(normalized_cfg.get("url") or mode or "unknown")
    orchestrator = deps.orchestrator_cls(scan_id=scan_id, target_url=target_ref)
    execution_payload: Dict[str, Any] = {}
    escalation_summary: Dict[str, Any] = {}

    async def _phase_preflight(_):
        return True

    async def _phase_discovery(_):
        return True

    async def _phase_execution(_):
        nonlocal execution_payload
        execution_payload = (await deps.run_omni_surface_scan_fn(user_id, normalized_cfg)) or {}
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
            findings_added += 1

        escalation_summary["findings_considered"] = findings_added
        if findings_added == 0:
            escalation_summary["status"] = "no_confirmed_findings"
            deps.state.omni_meta[user_id]["escalation"] = escalation_summary
            return True

        chains = chain_orch.discover_chains()
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
        return True

    async def _phase_verdict(_):
        return True

    try:
        await orchestrator.execute_phase(deps.orchestrator_phase.PREFLIGHT, _phase_preflight, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.DISCOVERY, _phase_discovery, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.EXECUTION, _phase_execution, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.ESCALATION, _phase_escalation, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.CORRELATION, _phase_correlation, orchestrator.context)
        await orchestrator.execute_phase(deps.orchestrator_phase.VERDICT, _phase_verdict, orchestrator.context)

        job = deps.job_get_fn(scan_id) or {}
        if job.get("status") == "running":
            try:
                findings = execution_payload.get("data", []) if isinstance(execution_payload, dict) else []
                is_vulnerable = any(f.get("vulnerable") for f in findings if isinstance(f, dict))
                verdict = "VULNERABLE" if is_vulnerable else "NO_VULNERABLE"

                history_data = {
                    "scan_id": scan_id,
                    "target": target_ref,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "config": normalized_cfg,
                    "verdict": verdict,
                    "message": "Escaneo Unificado Omnisurface completado (V4).",
                    "data": findings,
                    "evidenceCount": sum(1 for item in findings if isinstance(item, dict) and item.get("vulnerable")),
                    "resultsCount": len(findings),
                    "conclusive": True,
                    "mode": mode,
                    "kind": kind_norm,
                }

                secure_target = target_ref.replace("://", "_").translate(str.maketrans('\\/?*|"<>:', "_________"))
                filename = f"omni_{secure_target}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
                filepath = os.path.join(deps.history_dir, filename)

                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(history_data, f, indent=4, ensure_ascii=False)

                deps.job_update_fn(
                    scan_id,
                    status="completed",
                    finished_at=deps.job_now_fn(),
                    result_filename=filename,
                    vulnerable=1 if is_vulnerable else 0,
                )
                deps.logger.info(f"Historial JSON unificado generado exitosamente: {filename}")
            except Exception as hist_e:
                deps.logger.error(f"Error generando historial JSON para frontend: {hist_e}")
                deps.job_update_fn(scan_id, status="completed", finished_at=deps.job_now_fn())
    except asyncio.CancelledError:
        deps.job_update_fn(scan_id, status="stopped", finished_at=deps.job_now_fn(), error="stopped_by_user")
        raise
    except Exception as exc:
        deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=str(exc))
    finally:
        deps.state.omni_meta.pop(user_id, None)
