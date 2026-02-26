"""
Registered engine scan execution for omni web mode.
"""

from __future__ import annotations

from typing import Any, Dict, List


async def run_registered_engines_unified(
    *,
    target_url: str,
    omni_cfg: dict,
    configured_engine_list: List[str],
    results: List[Dict[str, Any]],
    coverage_ledger: Any,
    preflight_summary: Dict[str, Any],
    build_engine_vectors_for_target_fn: Any,
    broadcast_log_fn: Any,
    conclusive_blocker_cls: Any,
    preflight_fail_inc_fn: Any,
) -> bool:
    selected_engines = configured_engine_list or [
        "sqlmap",
        "zap",
        "nmap",
        "custom_payload",
        "advanced_payload",
        "burp",
    ]
    selected_engines = [str(engine).strip().lower() for engine in selected_engines if str(engine).strip()]
    selected_engines = list(dict.fromkeys(selected_engines))
    preflight_summary["checked"] = selected_engines

    try:
        from engines import EngineOrchestrator, list_engines
    except Exception as exc:
        preflight_summary["ok"] = False
        err_code = f"engines_subsystem:{type(exc).__name__}"
        preflight_summary["missing"] = [err_code]
        coverage_ledger.deps_missing = list(dict.fromkeys([*(coverage_ledger.deps_missing or []), err_code]))
        preflight_fail_inc_fn(err_code)
        coverage_ledger.add_blocker(
            conclusive_blocker_cls(
                category="missing_engine",
                detail=f"engine subsystem unavailable: {type(exc).__name__}",
                phase="preflight",
                recoverable=True,
            )
        )
        await broadcast_log_fn("CERBERUS_PRO", "WARN", "Engine orchestrator no disponible; se mantiene flujo base")
        return False

    available = {str(engine).strip().lower() for engine in (list_engines() or []) if str(engine).strip()}
    runnable = [engine for engine in selected_engines if engine in available]
    missing = [engine for engine in selected_engines if engine not in available]
    preflight_summary["missing"] = missing
    preflight_summary["executed"] = runnable

    if missing:
        preflight_summary["ok"] = False
        merged = [*(coverage_ledger.deps_missing or []), *[f"engine:{m}" for m in missing]]
        coverage_ledger.deps_missing = list(dict.fromkeys(merged))
        for missing_engine in missing:
            preflight_fail_inc_fn(f"engine:{missing_engine}")
            coverage_ledger.add_blocker(
                conclusive_blocker_cls(
                    category="missing_engine",
                    detail=f"{missing_engine}",
                    phase="preflight",
                    recoverable=True,
                )
            )
        await broadcast_log_fn(
            "ORQUESTADOR",
            "WARNING",
            f"Motores no disponibles en runtime: {', '.join(missing)}",
        )

    if not runnable:
        await broadcast_log_fn("ORQUESTADOR", "WARNING", "No hay motores ejecutables para engine_scan")
        return False

    vectors_for_engines = build_engine_vectors_for_target_fn(target_url, omni_cfg)
    await broadcast_log_fn(
        "ORQUESTADOR",
        "INFO",
        f"Engine scan unificado: ejecutando {len(runnable)} motores en paralelo",
        {"engines": runnable, "vectors": len(vectors_for_engines)},
    )
    try:
        orch = EngineOrchestrator(enabled_engines=runnable)
        engine_findings = await orch.scan_all(target_url, vectors_for_engines)
    except Exception as exc:
        for engine in runnable:
            results.append(
                {
                    "vector": f"ENGINE_{str(engine).upper()}",
                    "vulnerable": False,
                    "evidence": [f"engine_error:{type(exc).__name__}"],
                    "exit_code": 1,
                    "command": [],
                    "error": type(exc).__name__,
                }
            )
        await broadcast_log_fn(
            "ORQUESTADOR",
            "ERROR",
            f"Fallo en ejecución de motores unificados: {type(exc).__name__}: {exc}",
        )
        return False

    findings_by_engine: Dict[str, List[Any]] = {engine: [] for engine in runnable}
    for finding in (engine_findings or []):
        engine_name = str(getattr(finding, "engine", "") or "").strip().lower()
        if engine_name not in findings_by_engine:
            findings_by_engine[engine_name] = []
        findings_by_engine[engine_name].append(finding)

    found_vulnerability = False
    for engine in runnable:
        engine_vector = f"ENGINE_{str(engine).upper()}"
        grouped = findings_by_engine.get(engine, [])
        if grouped:
            found_vulnerability = True
            for finding in grouped:
                ftype = getattr(getattr(finding, "type", None), "value", str(getattr(finding, "type", "unknown")))
                severity = getattr(
                    getattr(finding, "severity", None),
                    "value",
                    str(getattr(finding, "severity", "unknown")),
                )
                endpoint = str(getattr(finding, "endpoint", "") or "")
                parameter = str(getattr(finding, "parameter", "") or "")
                evidence = str(getattr(finding, "evidence", "") or "")
                confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
                findings_msg = f"{ftype}|sev={severity}|conf={confidence:.2f}|{endpoint}|{parameter}"
                if evidence:
                    findings_msg += f"|{evidence[:220]}"
                results.append(
                    {
                        "vector": engine_vector,
                        "vulnerable": True,
                        "evidence": [findings_msg],
                        "exit_code": 0,
                        "command": [],
                        "error": None,
                    }
                )
        else:
            results.append(
                {
                    "vector": engine_vector,
                    "vulnerable": False,
                    "evidence": [f"{engine}: no findings"],
                    "exit_code": 0,
                    "command": [],
                    "error": None,
                }
            )
    return found_vulnerability
