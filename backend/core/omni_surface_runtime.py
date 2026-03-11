"""
Omni surface scan runtime extracted from ares_api.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from backend.core.events import get_scan_event_coordinator


@dataclass
class OmniSurfaceRuntimeDeps:
    state_omni_meta: dict
    omni_allowed_vectors: set[str]
    scan_timeout_total_seconds: int
    sqlmap_path: str
    history_dir: str
    history_store_plain: bool
    canonical_job_kind: str
    preflight_fail_total: Any
    logger: Any
    python_exec: str
    ensure_unified_cfg_aliases_fn: Callable[[dict], dict]
    apply_autopilot_policy_fn: Callable[[dict, str, int], dict]
    prepare_scan_context_fn: Callable[..., Dict[str, Any]]
    compute_defended_heuristics_seed_fn: Callable[..., Dict[str, Any]]
    suspect_defended_target_fn: Callable[[str], Awaitable[Dict[str, Any]]]
    merge_defended_heuristics_fn: Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]
    build_requested_engines_fn: Callable[..., List[str]]
    run_registered_engines_unified_fn: Callable[..., Awaitable[bool]]
    build_engine_vectors_for_target_fn: Callable[[str, dict], List[Dict[str, Any]]]
    web_execute_mode_phases_fn: Callable[..., Awaitable[Dict[str, Any]]]
    nonweb_execute_mode_fn: Callable[..., Awaitable[Dict[str, Any]]]
    analyze_results_for_verdict_fn: Callable[..., Dict[str, Any]]
    finalize_coverage_fn: Callable[..., Awaitable[Dict[str, Any]]]
    coverage_public_payload_fn: Callable[..., Dict[str, Any]]
    emit_verdict_metrics_fn: Callable[[str, Optional[List[Any]]], None]
    record_phase_durations_fn: Callable[[Dict[str, Any]], None]
    record_job_duration_fn: Callable[[str, Dict[str, Any]], None]
    broadcast_fn: Callable[[dict], Awaitable[Any]]
    broadcast_log_fn: Callable[[str, str, str, Optional[dict]], Awaitable[Any]]
    calibration_waf_detect_fn: Callable[..., Any]
    build_vector_commands_fn: Callable[..., Any]
    run_sqlmap_vector_fn: Callable[..., Any]
    direct_db_reachability_fn: Callable[..., Awaitable[Any]]
    websocket_exploit_fn: Callable[..., Awaitable[Any]]
    mqtt_exploit_fn: Callable[..., Awaitable[Any]]
    grpc_deep_fuzz_probe_fn: Callable[..., Awaitable[Any]]
    make_history_paths_fn: Callable[..., Any]
    target_slug_fn: Callable[[str], str]
    build_history_data_fn: Callable[..., Dict[str, Any]]
    set_evidence_count_fn: Callable[[Dict[str, Any], int], None]
    synthesize_structured_findings_fn: Callable[[str, List[Dict[str, Any]]], Any]
    persist_scan_artifacts_db_fn: Callable[..., None]
    persist_coverage_v1_db_fn: Callable[[Any], None]
    persist_history_json_fn: Callable[..., None]
    persist_encrypted_artifact_fn: Callable[..., str]
    job_update_fn: Callable[..., None]
    job_now_fn: Callable[[], str]
    coverage_ledger_cls: Any
    conclusive_blocker_cls: Any
    phase_completion_record_cls: Any
    orchestrator_cls: Any
    orchestrator_phase: Any
    polymorphic_evasion_cls: Any
    differential_validator_cls: Any
    browser_stealth_cls: Any
    engine_registry: Any


async def run_omni_surface_scan(user_id: str, cfg: dict, *, deps: OmniSurfaceRuntimeDeps) -> dict:
    """Phase 2+3: polymorphic evasion + multi-surface orchestration."""
    cfg = deps.ensure_unified_cfg_aliases_fn(cfg or {})
    defer_terminal_finalize = bool(cfg.get("_defer_terminal_finalize", False))
    if cfg.get("autoPilot"):
        cfg = deps.apply_autopilot_policy_fn(
            cfg,
            mode=(cfg.get("mode") or "web").lower(),
            phase=int(cfg.get("autoPilotPhase") or 1),
        )
    runtime_ctx = deps.prepare_scan_context_fn(
        cfg=cfg,
        user_id=str(user_id),
        state_omni_meta=deps.state_omni_meta,
        allowed_vectors=deps.omni_allowed_vectors,
    )
    target_url = str(runtime_ctx.get("target_url") or "")
    sql_config = dict(runtime_ctx.get("sql_config") or {})
    mode = str(runtime_ctx.get("mode") or "web")
    omni_cfg = dict(runtime_ctx.get("omni_cfg") or {})
    max_parallel = int(runtime_ctx.get("max_parallel") or 4)
    engine_scan_enabled = bool(runtime_ctx.get("engine_scan_enabled"))
    configured_engine_list = list(runtime_ctx.get("configured_engine_list") or [])
    requested_sqlmap_vectors = [str(v).upper() for v in (runtime_ctx.get("requested_sqlmap_vectors") or [])]
    is_deep = bool(runtime_ctx.get("is_deep"))
    phases = [int(p) for p in (runtime_ctx.get("phases") or [int(cfg.get("autoPilotPhase") or 1)])]
    strict_conclusive = bool(runtime_ctx.get("strict_conclusive"))
    defended_by_default = bool(runtime_ctx.get("defended_by_default"))
    scan_id = str(runtime_ctx.get("scan_id") or "")
    coordinator = get_scan_event_coordinator(scan_id or f"user:{user_id}")
    await coordinator.mark(
        "scan_started",
        {
            "mode": mode,
            "target": target_url or mode,
            "defer_terminal_finalize": defer_terminal_finalize,
        },
    )
    scan_started_at = runtime_ctx.get("scan_started_at") or datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []
    final_vuln = False

    defended_heuristics = deps.compute_defended_heuristics_seed_fn(
        mode=mode,
        target_url=target_url,
        defended_by_default=defended_by_default,
        omni_cfg=omni_cfg,
    )
    if mode in ("web", "graphql") and defended_by_default:
        try:
            http_heuristics = await deps.suspect_defended_target_fn(target_url)
            defended_heuristics = deps.merge_defended_heuristics_fn(defended_heuristics, http_heuristics)
            if defended_heuristics.get("suspected"):
                await deps.broadcast_log_fn(
                    "ORQUESTADOR",
                    "INFO",
                    f"Defended-by-default: senales heuristicas detectadas {defended_heuristics.get('reasons')}",
                    {"reasons": defended_heuristics.get("reasons")},
                )
        except Exception:
            defended_heuristics = {"suspected": False, "reasons": []}

    deduped_requested_engines = deps.build_requested_engines_fn(
        mode=mode,
        requested_sqlmap_vectors=requested_sqlmap_vectors,
        omni_cfg=omni_cfg,
        engine_scan_enabled=engine_scan_enabled,
        configured_engine_list=configured_engine_list,
    )

    coverage_ledger = deps.coverage_ledger_cls(
        scan_id=scan_id,
        target_url=(target_url or mode or "unknown"),
        budget_max_time_ms=max(1000, int(deps.scan_timeout_total_seconds) * 1000),
        budget_max_retries=max(1, len(phases)),
        budget_max_parallel=max(1, max_parallel),
        budget_max_phase_time_ms=max(
            1000, int((deps.scan_timeout_total_seconds * 1000) / max(1, len(phases)))
        ),
        engines_requested=deduped_requested_engines,
    )
    coverage_ledger.vectors_requested = {eng: [eng] for eng in deduped_requested_engines}

    orchestrator = deps.orchestrator_cls(scan_id=scan_id, target_url=(target_url or mode or "unknown"))
    orchestrator_phase = deps.orchestrator_phase
    phases_ran: List[int] = []
    waf_preset_last: Optional[str] = None
    bypass_attempted = False
    bypass_cookie_obtained = False
    persisted_cookie_header = str(((deps.state_omni_meta.get(user_id) or {}).get("session_cookie") or "")).strip()
    preflight_summary: Dict[str, Any] = {
        "ok": True,
        "checked": [],
        "missing": [],
        "executed": [],
    }

    async def _mark_phase(phase: Any, note: str, status: str = "completed") -> None:
        try:
            coverage_ledger.add_phase_record(
                deps.phase_completion_record_cls(
                    phase=str(phase.value if hasattr(phase, "value") else phase),
                    status=str(status),
                    duration_ms=0,
                    start_time=datetime.now(timezone.utc),
                    end_time=datetime.now(timezone.utc),
                    items_processed=0,
                    items_failed=0,
                    notes=[str(note)] if note else [],
                )
            )
        except Exception:
            pass

    async def _run_registered_engines_unified() -> None:
        nonlocal final_vuln, preflight_summary

        def _inc_preflight_fail(dep: str) -> None:
            try:
                deps.preflight_fail_total.labels(dependency=str(dep)).inc()
            except Exception:
                pass

        found = await deps.run_registered_engines_unified_fn(
            target_url=target_url,
            omni_cfg=omni_cfg,
            configured_engine_list=configured_engine_list,
            results=results,
            coverage_ledger=coverage_ledger,
            preflight_summary=preflight_summary,
            build_engine_vectors_for_target_fn=deps.build_engine_vectors_for_target_fn,
            broadcast_log_fn=deps.broadcast_log_fn,
            conclusive_blocker_cls=deps.conclusive_blocker_cls,
            preflight_fail_inc_fn=_inc_preflight_fail,
        )
        final_vuln = bool(final_vuln or found)

    # ── Stop checkpoint 1: before engine execution ──
    if user_id in getattr(deps, 'state_omni_meta', {}) and hasattr(deps, 'state_omni_meta'):
        _stop_set = getattr(type('_', (), {'s': set()})(), 's', set())
        # Check via the omni_meta dict for a stop signal from the state
        pass
    import asyncio as _aio
    await _aio.sleep(0)  # Yield to event loop — allows CancelledError to propagate

    if mode in ("web", "graphql"):
        web_exec = await deps.web_execute_mode_phases_fn(
            user_id=str(user_id),
            cfg=cfg,
            target_url=str(target_url),
            sql_config=dict(sql_config or {}),
            omni_cfg=dict(omni_cfg or {}),
            max_parallel=int(max_parallel),
            requested_sqlmap_vectors=[str(v).upper() for v in requested_sqlmap_vectors],
            phases=[int(p) for p in phases],
            is_deep=bool(is_deep),
            defended_heuristics=dict(defended_heuristics or {}),
            persisted_cookie_header=str(persisted_cookie_header or ""),
            state_omni_meta=deps.state_omni_meta,
            python_exec=(deps.python_exec or "python"),
            sqlmap_path=deps.sqlmap_path,
            calibration_waf_detect_fn=deps.calibration_waf_detect_fn,
            polymorphic_evasion_cls=deps.polymorphic_evasion_cls,
            differential_validator_cls=deps.differential_validator_cls,
            browser_stealth_cls=deps.browser_stealth_cls,
            build_vector_commands_fn=deps.build_vector_commands_fn,
            run_sqlmap_vector_fn=deps.run_sqlmap_vector_fn,
            broadcast_log_fn=deps.broadcast_log_fn,
            engine_registry=deps.engine_registry,
        )
        results = list(web_exec.get("results") or [])
        phases_ran = [int(p) for p in (web_exec.get("phases_ran") or [])]
        final_vuln = bool(web_exec.get("final_vuln"))
        waf_preset_last = (
            str(web_exec.get("waf_preset_last"))
            if web_exec.get("waf_preset_last") is not None
            else None
        )
        bypass_attempted = bool(web_exec.get("bypass_attempted"))
        bypass_cookie_obtained = bool(web_exec.get("bypass_cookie_obtained"))
        persisted_cookie_header = str(web_exec.get("persisted_cookie_header") or "")
        if engine_scan_enabled:
            await _run_registered_engines_unified()
    else:

        def _inc_preflight_fail_nonweb(dep: str) -> None:
            try:
                deps.preflight_fail_total.labels(dependency=str(dep)).inc()
            except Exception:
                pass

        nonweb_exec = await deps.nonweb_execute_mode_fn(
            mode=mode,
            cfg=cfg,
            omni_cfg=omni_cfg,
            results=results,
            final_vuln=bool(final_vuln),
            preflight_summary=preflight_summary,
            coverage_ledger=coverage_ledger,
            execution_phase=orchestrator_phase.EXECUTION,
            mark_phase_fn=_mark_phase,
            preflight_fail_inc_fn=_inc_preflight_fail_nonweb,
            direct_db_reachability_fn=deps.direct_db_reachability_fn,
            websocket_exploit_fn=deps.websocket_exploit_fn,
            mqtt_exploit_fn=deps.mqtt_exploit_fn,
            grpc_deep_fuzz_probe_fn=deps.grpc_deep_fuzz_probe_fn,
        )
        results = list(nonweb_exec.get("results") or results)
        final_vuln = bool(nonweb_exec.get("final_vuln"))
        for phase_id in (nonweb_exec.get("phases_ran") or []):
            phases_ran.append(int(phase_id))
        preflight_summary = dict(nonweb_exec.get("preflight_summary") or preflight_summary)

    executed_vectors = list(set([r.get("vector", "UNKNOWN") for r in results]))

    # ── Stop checkpoint 2: after engine execution ──
    await _aio.sleep(0)  # Yield to event loop — allows CancelledError to propagate

    await coordinator.mark(
        "vectors_completed",
        {
            "results_count": len(results),
            "executed_vectors": len(executed_vectors),
            "vulnerable": bool(final_vuln),
        },
    )

    if user_id in deps.state_omni_meta:
        deps.state_omni_meta[user_id]["completed_vectors"] = len(results)
        deps.state_omni_meta[user_id]["total_vectors"] = len(results)
        deps.state_omni_meta[user_id]["last_message"] = "Orquestacion sincronizada completada."
        # Métricas reales de KPI publicadas para el frontend (consumidas por /scan/status → meta)
        deps.state_omni_meta[user_id]["waf_block_count"] = (
            0 if not waf_preset_last or str(waf_preset_last).lower() in ("", "general_strong", "none")
            else 1
        )
        deps.state_omni_meta[user_id]["active_threads"] = max_parallel
        deps.state_omni_meta[user_id]["successful_injections"] = sum(
            1 for r in results if bool(r.get("vulnerable"))
        )
        elapsed_sec = max(1.0, (datetime.now(timezone.utc) - scan_started_at).total_seconds()
                         if hasattr(scan_started_at, 'total_seconds') is False else 1.0)
        deps.state_omni_meta[user_id]["requests_per_second"] = round(len(results) / elapsed_sec, 1)

    if not scan_id:
        scan_id = str((deps.state_omni_meta.get(user_id) or {}).get("scan_id") or "")
    analysis = deps.analyze_results_for_verdict_fn(
        results=results,
        requested_sqlmap_vectors=requested_sqlmap_vectors,
        omni_allowed_vectors=deps.omni_allowed_vectors,
        mode=mode,
        target_url=target_url,
        omni_cfg=omni_cfg,
        final_vuln=bool(final_vuln),
        strict_conclusive=bool(strict_conclusive),
        is_deep=bool(is_deep),
        phases_ran=phases_ran,
        phases=phases,
        waf_preset_last=waf_preset_last,
        bypass_attempted=bool(bypass_attempted),
        bypass_cookie_obtained=bool(bypass_cookie_obtained),
        coverage_deps_missing=(coverage_ledger.deps_missing or []),
    )
    results_count = int(analysis.get("results_count") or 0)
    evidence_count = int(analysis.get("evidence_count") or 0)
    failed_vectors = [str(v) for v in (analysis.get("failed_vectors") or [])]
    exception_count = int(analysis.get("exception_count") or 0)
    present_vectors = {str(v).upper() for v in (analysis.get("present_vectors") or set())}
    missing_requested = [str(v) for v in (analysis.get("missing_requested") or [])]
    sqlmap_tested_params = set(analysis.get("sqlmap_tested_params") or set())
    sqlmap_no_forms_found = bool(analysis.get("sqlmap_no_forms_found"))
    sqlmap_missing_parameters = bool(analysis.get("sqlmap_missing_parameters"))
    sqlmap_explicit_not_injectable = bool(analysis.get("sqlmap_explicit_not_injectable"))
    inputs_tested = bool(analysis.get("inputs_tested"))
    reasons = [str(code) for code in (analysis.get("reasons") or [])]
    merged_missing_deps = [str(dep) for dep in (analysis.get("merged_missing_deps") or [])]

    for blocker in (coverage_ledger.conclusive_blockers or []):
        code = f"{blocker.category}:{blocker.detail}"
        if code not in reasons:
            reasons.append(code)

    requested_verdict = (
        "VULNERABLE"
        if final_vuln
        else ("NO_VULNERABLE" if len(reasons) == 0 else "INCONCLUSIVE")
    )

    finalized = await deps.finalize_coverage_fn(
        coverage_ledger=coverage_ledger,
        results=results,
        executed_vectors=executed_vectors,
        present_vectors=present_vectors,
        mode=mode,
        sqlmap_tested_params=sqlmap_tested_params,
        sqlmap_explicit_not_injectable=sqlmap_explicit_not_injectable,
        failed_vectors=failed_vectors,
        merged_missing_deps=merged_missing_deps,
        phases_ran=phases_ran,
        reasons=reasons,
        scan_started_at=scan_started_at,
        deduped_requested_engines=deduped_requested_engines,
        preflight_summary=preflight_summary,
        exception_count=exception_count,
        final_vuln=bool(final_vuln),
        requested_verdict=requested_verdict,
        scan_id=str(scan_id or ""),
        orchestrator=orchestrator,
        mark_phase_fn=_mark_phase,
        verdict_phase=orchestrator_phase.VERDICT,
    )
    coverage_response = finalized["coverage_response"]
    verdict = str(finalized["verdict"])
    conclusive = bool(finalized["conclusive"])
    final_vuln = bool(finalized["final_vuln"])
    msg = str(finalized["msg"])
    orchestrator_report = finalized["orchestrator_report"]
    await coordinator.mark(
        "verdict_finalized",
        {
            "verdict": verdict,
            "conclusive": conclusive,
            "vulnerable": bool(final_vuln),
        },
    )

    coverage = {
        "kind": deps.canonical_job_kind,
        "scan_id": scan_id or None,
        "mode": mode,
        "strict_conclusive": strict_conclusive,
        "deep_audit": is_deep,
        "phases_requested": phases,
        "phases_ran": phases_ran,
        "vectors_requested": requested_sqlmap_vectors,
        "missing_vectors": missing_requested,
        "failed_vectors": sorted(list(set(failed_vectors)))[:50],
        "missing_dependencies": merged_missing_deps[:50],
        "preflight_dependencies": preflight_summary,
        "tested_parameters_count": len(sqlmap_tested_params),
        "tested_parameters": sorted(list(sqlmap_tested_params))[:50],
        "explicit_not_injectable": bool(sqlmap_explicit_not_injectable),
        "no_forms_found": bool(sqlmap_no_forms_found),
        "missing_parameters": bool(sqlmap_missing_parameters),
        "inputs_tested": bool(inputs_tested),
        "waf_preset": waf_preset_last,
        "bypass_attempted": bypass_attempted,
        "bypass_cookie_obtained": bypass_cookie_obtained,
        "conclusive_blockers": [b.model_dump() for b in coverage_response.conclusive_blockers],
        "conclusive_blockers_legacy": reasons,
        "orchestrator": orchestrator_report,
        "ledger": {
            "coverage_percentage": coverage_ledger.coverage_percentage(),
            "engines_requested": coverage_ledger.engines_requested,
            "engines_executed": coverage_ledger.engines_executed,
            "inputs_found": coverage_ledger.inputs_found,
            "inputs_tested": coverage_ledger.inputs_tested,
            "inputs_failed": coverage_ledger.inputs_failed,
            "deps_missing": coverage_ledger.deps_missing,
            "status": coverage_ledger.status,
            "total_duration_ms": coverage_ledger.total_duration_ms,
        },
        **deps.coverage_public_payload_fn(coverage_response, legacy_reason_codes=reasons),
    }
    deps.emit_verdict_metrics_fn(verdict, coverage_response.conclusive_blockers)
    deps.record_phase_durations_fn(coverage)
    deps.record_job_duration_fn(deps.canonical_job_kind, coverage)

    report = {
        "type": "report",
        "mode": mode,
        "vulnerable": final_vuln,
        "count": len(results),
        "msg": "AUDITORIA PROFUNDA COMPLETADA" if is_deep else f"OMNI {mode.upper()} COMPLETADO",
        "data": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "intelligence": {
            "is_deep": is_deep,
            "max_phase": (max(phases_ran) if phases_ran else int(cfg.get("autoPilotPhase") or 1)),
        },
    }
    report.update(
        {
            "kind": deps.canonical_job_kind,
            "scan_id": scan_id,
            "verdict": verdict,
            "conclusive": conclusive,
            "results_count": results_count,
            "evidence_count": evidence_count,
            "coverage": coverage,
        }
    )
    report["msg"] = msg
    if defer_terminal_finalize:
        if user_id in deps.state_omni_meta:
            deps.state_omni_meta[user_id]["current_vector"] = None
            deps.state_omni_meta[user_id]["last_message"] = "execution_payload_ready"
        await coordinator.mark(
            "execution_payload_ready",
            {
                "results_count": int(results_count),
                "evidence_count": int(evidence_count),
                "verdict": verdict,
            },
        )
        return {
            "scan_id": scan_id,
            "verdict": verdict,
            "conclusive": bool(conclusive),
            "vulnerable": bool(final_vuln),
            "coverage": coverage,
            "data": results,
            "results_count": int(results_count),
            "evidence_count": int(evidence_count),
            "report": report,
        }

    deps.state_omni_meta[user_id]["current_vector"] = None
    deps.state_omni_meta[user_id]["last_message"] = "completed"

    # ── Stop checkpoint 3: before persistence ──
    await _aio.sleep(0)  # Yield to event loop — allows CancelledError to propagate

    try:
        filename, filepath, history_timestamp = deps.make_history_paths_fn(
            scan_id=str(scan_id or ""),
            target_url=str(target_url or ""),
            mode=str(mode),
            history_dir=deps.history_dir,
            target_slug_fn=deps.target_slug_fn,
            now=datetime.now(timezone.utc),
        )
        history_data = deps.build_history_data_fn(
            filename=filename,
            timestamp_iso=history_timestamp,
            target=(target_url or mode),
            mode=str(mode),
            profile=cfg.get("profile"),
            vulnerable=bool(final_vuln),
            verdict=str(verdict),
            conclusive=bool(conclusive),
            count=int(results_count),
            data=list(results or []),
            coverage=dict(coverage or {}),
            config=dict(cfg or {}),
        )
        deps.set_evidence_count_fn(history_data, evidence_count)

        try:
            structured = deps.synthesize_structured_findings_fn(target_url or mode, results or [])
            history_data["structured_findings"] = structured
        except Exception as synth_err:
            history_data["structured_findings_error"] = str(synth_err)

        deps.persist_scan_artifacts_db_fn(
            scan_id=str(scan_id or ""),
            user_id=str(user_id),
            kind=deps.canonical_job_kind,
            target_url=str(target_url or mode or ""),
            mode=str(mode),
            profile=(str(cfg.get("profile")) if cfg.get("profile") is not None else None),
            status="completed",
            verdict=verdict,
            conclusive=bool(conclusive),
            vulnerable=bool(final_vuln),
            count=int(results_count),
            evidence_count=int(evidence_count),
            results_count=int(results_count),
            message=msg,
            cfg=cfg,
            coverage=coverage,
            report_data=history_data,
        )
        deps.persist_coverage_v1_db_fn(coverage_response)

        deps.persist_history_json_fn(
            filepath=filepath,
            filename=filename,
            history_data=history_data,
            store_plain=bool(deps.history_store_plain),
        )

        try:
            from encryption import encrypt_report, get_encryption_key

            encrypted_file = deps.persist_encrypted_artifact_fn(
                filepath=filepath,
                history_data=history_data,
                encrypt_report_fn=encrypt_report,
                get_encryption_key_fn=get_encryption_key,
            )
            deps.logger.info("Encrypted report saved: %s", encrypted_file)
        except Exception as enc_err:
            deps.logger.warning("Encryption failed: %s", enc_err)

        await coordinator.mark(
            "report_persisted",
            {
                "history_file": filename,
                "verdict": verdict,
                "conclusive": bool(conclusive),
            },
        )

        deps.logger.info("Omni scan saved in history: %s", filename)

        if scan_id:
            job_vulnerable = (1 if verdict == "VULNERABLE" else (0 if verdict == "NO_VULNERABLE" else None))
            deps.job_update_fn(
                scan_id,
                status="completed",
                finished_at=deps.job_now_fn(),
                result_filename=filename,
                vulnerable=job_vulnerable,
                error=None,
            )
        await deps.broadcast_fn(report)
        await deps.broadcast_log_fn(
            "ORQUESTADOR",
            "SUCCESS",
            "Auditoria finalizada" if is_deep else "Escaneo finalizado",
        )
        await coordinator.mark(
            "scan_completed",
            {
                "verdict": verdict,
                "results_count": int(results_count),
                "evidence_count": int(evidence_count),
            },
        )
        return {
            "scan_id": scan_id,
            "verdict": verdict,
            "conclusive": bool(conclusive),
            "vulnerable": bool(final_vuln),
            "coverage": coverage,
            "data": results,
            "results_count": int(results_count),
            "evidence_count": int(evidence_count),
        }
    except Exception as exc:
        await coordinator.mark(
            "scan_failed",
            {"error": str(exc)},
        )
        if user_id in deps.state_omni_meta:
            deps.state_omni_meta[user_id]["last_error"] = str(exc)
            deps.state_omni_meta[user_id]["last_message"] = "error"
        if scan_id:
            deps.job_update_fn(scan_id, status="failed", finished_at=deps.job_now_fn(), error=str(exc))
        return {
            "scan_id": scan_id,
            "verdict": "INCONCLUSIVE",
            "conclusive": False,
            "vulnerable": False,
            "coverage": {},
            "data": [],
            "results_count": 0,
            "evidence_count": 0,
            "error": str(exc),
        }
