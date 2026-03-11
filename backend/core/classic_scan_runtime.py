"""
Classic scan reader/runtime helpers extracted from ares_api.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List

from backend.core.coverage_contract_v1 import (
    COVERAGE_SCHEMA_VERSION_V1,
    CoveragePhaseRecordV1,
    CoverageResponseV1,
    CoverageSummaryV1,
    CoverageVectorRecordV1,
    VectorRecordsPageV1,
    adapt_legacy_blockers,
    issue_verdict_v1,
)


@dataclass
class ClassicScanRuntimeDeps:
    state: Any
    logger: Any
    smart_filter_cls: Any
    finding_parser_cls: Any
    broadcast_fn: Callable[[Dict[str, Any]], Awaitable[None]]
    sanitize_line_fn: Callable[[str], str]
    translate_log_fn: Callable[[str], str]
    detect_defensive_measures_fn: Callable[[str], Dict[str, Any]]
    autopilot_max_phase: int
    apply_autopilot_policy_fn: Callable[[dict, str, int], dict]
    sqlmap_path: str
    sqlmap_non_interactive_flags_fn: Callable[[], List[str]]
    header_scrubber_cls: Any
    start_sqlmap_process_fn: Callable[[List[str]], Any]
    terminate_process_tree_fn: Callable[[Any], None]
    job_update_fn: Callable[..., Awaitable[None]]
    job_now_fn: Callable[[], str]
    canonical_job_kind: str
    coverage_public_payload_fn: Callable[..., Dict[str, Any]]
    emit_verdict_metrics_fn: Callable[..., None]
    record_phase_durations_from_coverage_fn: Callable[[Dict[str, Any]], None]
    record_job_duration_fn: Callable[[str, Dict[str, Any]], None]
    build_multi_profile_reports_fn: Callable[..., Any]
    persist_scan_artifacts_db_fn: Callable[..., Awaitable[None]]
    persist_coverage_v1_db_fn: Callable[[CoverageResponseV1], Awaitable[None]]
    target_slug_fn: Callable[[str], str]
    history_dir: str
    history_store_plain: bool
    audit_log_fn: Callable[..., Awaitable[Any]]
    cleanup_scan_runtime_fn: Callable[[str], None]


def _reason_human(reason_code: str) -> str:
    if reason_code.startswith("engine_exit_code:"):
        return f"motor termino con codigo {reason_code.split(':', 1)[1]}"
    if reason_code == "no_forms_found":
        return "no se encontraron formularios/inputs para probar"
    if reason_code == "missing_parameters":
        return "faltan parametros para probar"
    if reason_code == "no_parameters_tested":
        return "no se detectaron parametros probables para testear"
    if reason_code == "autopilot_not_exhausted":
        return "Auto-Pilot no agoto todas las fases"
    if reason_code.startswith("defensive:"):
        return "contramedidas detectadas (WAF/rate-limit/honeypot)"
    return reason_code


async def start_next_phase(user_id: str, scan_info: dict, deps: ClassicScanRuntimeDeps) -> None:
    """Orchestrate the next phase of an Auto-Pilot scan."""
    phase = scan_info.get("phase", 1)
    cfg = deps.apply_autopilot_policy_fn(scan_info.get("config", {}), mode="classic", phase=phase)
    scan_info["config"] = cfg
    target_url = cfg.get("url", "")
    sql_config = cfg.get("sqlMap", {})

    cmd = [sys.executable, deps.sqlmap_path, "--smart", "--forms", "-u", target_url]
    cmd.extend(deps.sqlmap_non_interactive_flags_fn())

    cmd.extend(
        [
            f"--threads={int(sql_config.get('threads', 5))}",
            f"--level={int(sql_config.get('level', 3))}",
            f"--risk={int(sql_config.get('risk', 2))}",
        ]
    )
    if sql_config.get("technique"):
        cmd.append(f"--technique={sql_config['technique']}")
    if sql_config.get("tamper"):
        cmd.append(f"--tamper={sql_config['tamper']}")
    if sql_config.get("timeout"):
        cmd.append(f"--timeout={int(sql_config['timeout'])}")
    if float(sql_config.get("auto_delay", 0)) > 0:
        cmd.append(f"--delay={float(sql_config['auto_delay'])}")

    cmd.extend(deps.header_scrubber_cls.get_sqlmap_arguments())
    try:
        if deps.state.proc and deps.state.proc.poll() is None:
            deps.terminate_process_tree_fn(deps.state.proc)

        deps.state.proc = deps.start_sqlmap_process_fn(cmd)
        scan_info["pid"] = deps.state.proc.pid
        if scan_info.get("scan_id"):
            await deps.job_update_fn(
                str(scan_info["scan_id"]),
                pid=int(deps.state.proc.pid),
                started_at=deps.job_now_fn(),
                status="running",
            )
        return
    except Exception as exc:
        deps.logger.error(f"Auto-Pilot Phase {phase} error: {str(exc)}")
        await deps.broadcast_fn(
            {
                "type": "log",
                "component": "SISTEMA",
                "level": "ERROR",
                "msg": f"Auto-Pilot fallo al iniciar Fase {phase}: {str(exc)}",
            }
        )


async def scan_reader_task(user_id: str, deps: ClassicScanRuntimeDeps) -> None:
    """Read scan output and broadcast via WebSocket."""

    vuln_found = False
    extracted_data: List[str] = []
    log_buffer: List[str] = []
    scan_info = deps.state.active_scans.get(user_id, {})
    smart_filter = deps.smart_filter_cls()
    finding_parser = deps.finding_parser_cls()

    await asyncio.sleep(0.5)
    ret = deps.state.proc.poll()
    if ret is not None:
        deps.logger.error(f"El motor termino inmediatamente con codigo: {ret}")
        await deps.broadcast_fn(
            {
                "type": "log",
                "component": "SISTEMA",
                "level": "ERROR",
                "msg": f"Motor detenido prematuramente (Code: {ret})",
            }
        )
        scan_id = str(scan_info.get("scan_id") or "")
        if scan_id:
            await deps.job_update_fn(
                scan_id,
                status="failed",
                finished_at=deps.job_now_fn(),
                error=f"engine_exited_early:{ret}",
            )
        return

    try:
        while deps.state.proc and deps.state.proc.poll() is None:
            line = await asyncio.to_thread(deps.state.proc.stdout.readline)
            if not line:
                break

            line = line.strip()
            if not line:
                continue
            log_buffer.append(line)

            safe_line = deps.sanitize_line_fn(line)
            severity = smart_filter.classify(safe_line)
            finding_parser.feed(safe_line)

            translated_line = deps.translate_log_fn(safe_line)
            if smart_filter.keep_for_clean_view(severity):
                level_map = {
                    "CRITICAL": "ERROR",
                    "HIGH": "WARN",
                    "MEDIUM": "INFO",
                }
                await deps.broadcast_fn(
                    {
                        "type": "log",
                        "component": "CERBERUS_PRO",
                        "level": level_map.get(severity, "INFO"),
                        "msg": translated_line,
                        "severity": severity,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            vuln_indicators = [
                " identified the following injection point(s)",
                " is vulnerable",
                " appears to be injectable",
                "back-end dbms is ",
                "confirming the following extraction point",
            ]
            if any(indicator in line.lower() for indicator in vuln_indicators) or "[+]" in line:
                vuln_found = True

            data_indicators = [
                "retrieved:",
                "database:",
                "table:",
                "column:",
                "current user:",
                "current database:",
                "dumped",
                "records:",
                "csv results",
            ]
            is_result = any(ki in line.lower() for ki in data_indicators)
            is_table = line.count("|") >= 2

            is_noise = any(
                x in line
                for x in ["|_", "---", "https://sqlmap.org", "using '", ".csv' as the CSV"]
            )
            is_empty_retrieval = (
                line.lower().strip() == "retrieved:" or line.lower().strip().endswith("retrieved: .")
            )

            if (is_result or is_table) and not is_noise and not is_empty_retrieval:
                if len(safe_line) > 5:
                    clean_data = re.sub(r"\[\d+:\d+:\d+\] \[\w+\] ", "", safe_line)
                    if "..." not in clean_data or " (done)" in clean_data:
                        if clean_data not in extracted_data:
                            extracted_data.append(clean_data)

        if not vuln_found and deps.state.active_scans.get(user_id, {}).get("autoPilot"):
            scan_info = deps.state.active_scans[user_id]
            current_phase = scan_info.get("phase", 1)
            max_phase = int(scan_info.get("max_phase") or deps.autopilot_max_phase)

            accumulated_log = "\n".join(log_buffer[-1000:]) if log_buffer else ""
            defensive = deps.detect_defensive_measures_fn(accumulated_log)

            if defensive["recommended_action"] == "abort":
                deps.logger.warning(
                    f"Auto-Pilot: Defensive measures detected - aborting escalation. {defensive}"
                )
                await deps.broadcast_fn(
                    {
                        "type": "log",
                        "component": "SISTEMA",
                        "level": "WARNING",
                        "msg": (
                            "Auto-Pilot: Contramedidas detectadas "
                            f"(WAF={defensive['waf_detected']}, "
                            f"Rate-Limited={defensive['rate_limited']}, "
                            f"Honeypot={defensive['honeypot_probability']:.0%}). Abortando escalada."
                        ),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            elif defensive["recommended_action"] == "reduce_aggression":
                deps.logger.info(
                    f"Auto-Pilot: Reducing aggression due to defensive measures. {defensive}"
                )
                await deps.broadcast_fn(
                    {
                        "type": "log",
                        "component": "SISTEMA",
                        "level": "WARNING",
                        "msg": (
                            "Auto-Pilot: Ajustando agresividad - medidas defensivas detectadas. "
                            "Reduciendo hilos y aumentando delay."
                        ),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                if current_phase < max_phase:
                    next_phase = current_phase + 1
                    cfg = scan_info.get("config", {})
                    sql_cfg = cfg.get("sqlMap", {})
                    sql_cfg["threads"] = max(1, int(sql_cfg.get("threads", 5)) // 2)
                    sql_cfg["auto_delay"] = float(sql_cfg.get("auto_delay", 1.0)) * 2
                    cfg["sqlMap"] = sql_cfg
                    scan_info["config"] = cfg
                    scan_info["phase"] = next_phase
                    if scan_info.get("scan_id"):
                        await deps.job_update_fn(str(scan_info["scan_id"]), phase=int(next_phase), status="running")
                    await deps.broadcast_fn(
                        {
                            "type": "log",
                            "component": "SISTEMA",
                            "level": "WARNING",
                            "msg": (
                                "Auto-Pilot: Escalando con cautela a "
                                f"Fase {next_phase}/{max_phase} (agresividad reducida)"
                            ),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                    await start_next_phase(user_id, scan_info, deps)
                    await scan_reader_task(user_id, deps)
                    return
            elif current_phase < max_phase:
                next_phase = current_phase + 1
                if scan_info.get("scan_id"):
                    await deps.job_update_fn(str(scan_info["scan_id"]), phase=int(next_phase), status="running")
                deps.logger.info(
                    f"Auto-Pilot: No se hallaron vulnerabilidades en Fase {current_phase}. "
                    f"Escalando a Fase {next_phase}..."
                )

                await deps.broadcast_fn(
                    {
                        "type": "log",
                        "component": "SISTEMA",
                        "level": "WARNING",
                        "msg": (
                            "Auto-Pilot: Ajustando estrategia... Escalando a "
                            f"Fase {next_phase}/{max_phase} (Mayor profundidad)"
                        ),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

                scan_info["phase"] = next_phase
                await start_next_phase(user_id, scan_info, deps)
                await scan_reader_task(user_id, deps)
                return

        exit_code = None
        try:
            exit_code = deps.state.proc.poll() if deps.state.proc else None
        except Exception:
            exit_code = None

        scan_id = str(scan_info.get("scan_id") or "")
        target_url = scan_info.get("config", {}).get("url", "unknown")
        auto_pilot_enabled = bool(scan_info.get("autoPilot"))
        current_phase = int(scan_info.get("phase") or 1)
        max_phase = int(scan_info.get("max_phase") or deps.autopilot_max_phase)

        safe_log_tail = "\n".join(
            [deps.sanitize_line_fn(x) for x in (log_buffer[-1500:] if log_buffer else [])]
        )
        low_tail = safe_log_tail.lower()

        no_forms_found = ("no forms found" in low_tail) or ("no forms were found" in low_tail)
        explicit_not_injectable = "all tested parameters do not appear to be injectable" in low_tail
        must_provide_param = "you must provide at least one parameter" in low_tail

        tested_params = set()
        try:
            for m in re.finditer(r"(?i)\b(?:get|post|uri|cookie)\s+parameter\s+'([^']+)'", safe_log_tail):
                tested_params.add(m.group(1))
        except Exception:
            tested_params = set()

        defensive_final = deps.detect_defensive_measures_fn(safe_log_tail)

        reasons: List[str] = []

        if vuln_found:
            requested_verdict = "VULNERABLE"
        else:
            if exit_code not in (None, 0):
                reasons.append(f"engine_exit_code:{exit_code}")
            if no_forms_found:
                reasons.append("no_forms_found")
            if must_provide_param:
                reasons.append("missing_parameters")
            if (len(tested_params) == 0) and (not explicit_not_injectable):
                reasons.append("no_parameters_tested")
            if auto_pilot_enabled and current_phase < max_phase:
                reasons.append("autopilot_not_exhausted")
            if str(defensive_final.get("recommended_action") or "continue") != "continue":
                reasons.append(f"defensive:{defensive_final.get('recommended_action')}")

            requested_verdict = "NO_VULNERABLE" if len(reasons) == 0 else "INCONCLUSIVE"

        tested_inputs_count = len(tested_params) if len(tested_params) > 0 else (1 if explicit_not_injectable else 0)
        sqlmap_executed = bool((exit_code in (None, 0)) and (len(log_buffer) > 0))
        summary_v1 = CoverageSummaryV1(
            coverage_percentage=(100.0 if sqlmap_executed else 0.0),
            engines_requested=["SQLMAP"],
            engines_executed=(["SQLMAP"] if sqlmap_executed else []),
            inputs_found=max(0, int(tested_inputs_count)),
            inputs_tested=max(0, int(tested_inputs_count)),
            inputs_failed=(0 if exit_code in (None, 0) else 1),
            deps_missing=[],
            preflight_ok=True,
            execution_ok=(exit_code in (None, 0)),
            verdict_phase_completed=True,
            status=("completed" if exit_code in (None, 0) else "failed"),
            total_duration_ms=0,
            redactions_applied=True,
        )
        blockers_v1 = adapt_legacy_blockers(reasons, default_phase="verdict")
        verdict_decision = issue_verdict_v1(
            has_confirmed_finding=bool(vuln_found),
            requested_verdict=requested_verdict,
            summary=summary_v1,
            blockers=blockers_v1,
        )
        verdict = verdict_decision.verdict
        conclusive = verdict_decision.conclusive
        vulnerable_final = verdict_decision.vulnerable
        reason = (
            str(verdict_decision.blockers[0].message)
            if verdict_decision.blockers
            else (_reason_human(reasons[0]) if reasons else "")
        )
        if verdict == "VULNERABLE":
            msg = "VULNERABLE - Injection detected"
        elif verdict == "NO_VULNERABLE":
            msg = "NO VULNERABLE - Sin hallazgos con cobertura completa"
        else:
            msg = f"INCONCLUSO - {reason}" if reason else "INCONCLUSO - Cobertura insuficiente"

        vector_records = [
            CoverageVectorRecordV1(
                vector_id="classic_sqlmap",
                vector_name="SQLMAP",
                engine="SQLMAP",
                status=("EXECUTED" if sqlmap_executed else ("FAILED" if exit_code not in (None, 0) else "PENDING")),
                inputs_tested=max(0, int(tested_inputs_count)),
                duration_ms=0,
                error=(f"exit_code:{exit_code}" if exit_code not in (None, 0) else None),
            )
        ]
        coverage_response = CoverageResponseV1(
            version=COVERAGE_SCHEMA_VERSION_V1,
            scan_id=scan_id or "",
            job_status="completed",
            verdict=verdict,
            conclusive=bool(conclusive),
            vulnerable=bool(vulnerable_final),
            coverage_summary=summary_v1,
            conclusive_blockers=verdict_decision.blockers,
            phase_records=[
                CoveragePhaseRecordV1(
                    phase="execution",
                    status=("completed" if exit_code in (None, 0) else "failed"),
                    duration_ms=0,
                    items_processed=max(0, len(log_buffer)),
                    items_failed=(0 if exit_code in (None, 0) else 1),
                    notes=[],
                ),
                CoveragePhaseRecordV1(
                    phase="verdict",
                    status="completed",
                    duration_ms=0,
                    items_processed=1,
                    items_failed=0,
                    notes=[],
                ),
            ],
            vector_records_page=VectorRecordsPageV1(
                limit=50,
                cursor=0,
                next_cursor=None,
                has_more=False,
                items=vector_records,
            ),
        )

        coverage = {
            "kind": deps.canonical_job_kind,
            "scan_id": scan_id or None,
            "target": target_url,
            "autopilot": auto_pilot_enabled,
            "phase": current_phase,
            "max_phase": max_phase,
            "engine_exit_code": exit_code,
            "tested_parameters_count": len(tested_params),
            "tested_parameters": sorted(list(tested_params))[:50],
            "explicit_not_injectable": bool(explicit_not_injectable),
            "no_forms_found": bool(no_forms_found),
            "defensive": defensive_final,
            "conclusive_blockers": [b.model_dump() for b in coverage_response.conclusive_blockers],
            "conclusive_blockers_legacy": reasons,
            **deps.coverage_public_payload_fn(coverage_response, legacy_reason_codes=reasons),
        }
        deps.emit_verdict_metrics_fn(verdict, coverage_response.conclusive_blockers)
        deps.record_phase_durations_from_coverage_fn(coverage)
        deps.record_job_duration_fn(deps.canonical_job_kind, coverage)

        filter_stats = smart_filter.stats()
        parser_summary = finding_parser.summary()
        profiles = deps.build_multi_profile_reports_fn(
            target=target_url,
            vulnerable=bool(vulnerable_final),
            verdict=verdict,
            conclusive=conclusive,
            extracted_data=extracted_data,
            filter_stats=filter_stats,
            parser_summary=parser_summary,
        )

        report = {
            "type": "report",
            "kind": deps.canonical_job_kind,
            "scan_id": scan_id,
            "verdict": verdict,
            "conclusive": conclusive,
            "vulnerable": bool(vulnerable_final),
            "count": len(extracted_data),
            "evidence_count": len(extracted_data),
            "results_count": len(extracted_data),
            "msg": msg,
            "data": extracted_data,
            "coverage": coverage,
            "intelligence": {
                "filter": filter_stats,
                "parser": parser_summary,
            },
            "profiles": profiles,
        }

        await deps.broadcast_fn(report)

        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            target_clean = deps.target_slug_fn(scan_info.get("config", {}).get("url", "unknown"))
            if scan_id:
                filename = f"scan_{timestamp}_{scan_id}_{target_clean}.json"
            else:
                filename = f"scan_{timestamp}_{target_clean}.json"
            filepath = os.path.join(deps.history_dir, filename)

            history_data = {
                "id": filename,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": scan_info.get("config", {}).get("url"),
                "profile": scan_info.get("config", {}).get("profile"),
                "vulnerable": bool(vulnerable_final),
                "verdict": verdict,
                "conclusive": conclusive,
                "count": len(extracted_data),
                "evidence_count": len(extracted_data),
                "results_count": len(extracted_data),
                "data": extracted_data,
                "coverage": coverage,
                "config": scan_info.get("config"),
                "intelligence": {
                    "filter": filter_stats,
                    "parser": parser_summary,
                },
                "profiles": profiles,
            }

            await deps.persist_scan_artifacts_db_fn(
                scan_id=str(scan_id or ""),
                user_id=str(user_id),
                kind=deps.canonical_job_kind,
                target_url=str(scan_info.get("config", {}).get("url") or ""),
                mode=None,
                profile=(
                    str(scan_info.get("config", {}).get("profile"))
                    if scan_info.get("config", {}).get("profile") is not None
                    else None
                ),
                status="completed",
                verdict=verdict,
                conclusive=bool(conclusive),
                vulnerable=bool(vulnerable_final),
                count=len(extracted_data),
                evidence_count=len(extracted_data),
                results_count=len(extracted_data),
                message=msg,
                cfg=(scan_info.get("config") or {}),
                coverage=coverage,
                report_data=history_data,
            )
            await deps.persist_coverage_v1_db_fn(coverage_response)

            if deps.history_store_plain:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(history_data, f, indent=2, ensure_ascii=False)
            else:
                safe_summary = {
                    "id": filename,
                    "timestamp": history_data.get("timestamp"),
                    "target": history_data.get("target"),
                    "profile": history_data.get("profile"),
                    "vulnerable": history_data.get("vulnerable"),
                    "verdict": history_data.get("verdict"),
                    "conclusive": history_data.get("conclusive"),
                    "count": history_data.get("count"),
                    "encrypted": True,
                    "artifact": os.path.basename(filepath).replace(".json", ".enc"),
                }
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(safe_summary, f, indent=2, ensure_ascii=False)

            try:
                from encryption import encrypt_report, get_encryption_key

                enc_key = get_encryption_key()
                encrypted_path = filepath.replace(".json", ".enc")
                with open(encrypted_path, "wb") as ef:
                    ef.write(encrypt_report(history_data, enc_key))
                deps.logger.info(f"Encrypted report saved: {os.path.basename(encrypted_path)}")
            except Exception as enc_err:
                deps.logger.warning(f"Encryption failed: {enc_err}")

            deps.logger.info(f"Scan guardado en historial: {filename}")
            if scan_id:
                job_vulnerable = 1 if verdict == "VULNERABLE" else (0 if verdict == "NO_VULNERABLE" else None)
                await deps.job_update_fn(
                    scan_id,
                    status="completed",
                    finished_at=deps.job_now_fn(),
                    result_filename=filename,
                    vulnerable=job_vulnerable,
                )
        except Exception as save_err:
            deps.logger.error(f"No se pudo guardar el historial: {str(save_err)}")
            scan_id = str(scan_info.get("scan_id") or "")
            if scan_id:
                await deps.job_update_fn(
                    scan_id,
                    status="failed",
                    finished_at=deps.job_now_fn(),
                    error=str(save_err),
                )

        await deps.audit_log_fn(
            user_id=user_id,
            action="scan_completed",
            resource_type="scan",
            status="success",
        )
        deps.cleanup_scan_runtime_fn(user_id)

    except Exception as exc:
        deps.logger.error(f"Scan error: {str(exc)}")
        await deps.broadcast_fn(
            {
                "type": "log",
                "component": "SISTEMA",
                "level": "ERROR",
                "msg": f"Error en scan: {str(exc)}",
            }
        )
        scan_info = deps.state.active_scans.get(user_id, {})
        scan_id = str(scan_info.get("scan_id") or "")
        if scan_id:
            await deps.job_update_fn(
                scan_id,
                status="failed",
                finished_at=deps.job_now_fn(),
                error=str(exc),
            )
        deps.cleanup_scan_runtime_fn(user_id)
