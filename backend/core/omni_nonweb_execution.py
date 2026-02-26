"""
Non-web mode execution helpers for omni scans.
"""

from __future__ import annotations

from typing import Any, Dict, List


async def execute_nonweb_mode(
    *,
    mode: str,
    cfg: dict,
    omni_cfg: dict,
    results: List[Dict[str, Any]],
    final_vuln: bool,
    preflight_summary: Dict[str, Any],
    coverage_ledger: Any,
    execution_phase: Any,
    mark_phase_fn: Any,
    preflight_fail_inc_fn: Any,
    direct_db_reachability_fn: Any,
    websocket_exploit_fn: Any,
    mqtt_exploit_fn: Any,
    grpc_deep_fuzz_probe_fn: Any,
) -> Dict[str, Any]:
    phases_ran = [int(cfg.get("autoPilotPhase") or 1)]
    timeout_non_web = float((omni_cfg.get("timeout") or 10))

    if mode == "direct_db":
        db_cfg = omni_cfg.get("directDb", {}) or {}
        engine = str(db_cfg.get("engine") or "mysql")
        host = str(db_cfg.get("host") or "")
        port = int(db_cfg.get("port") or (5432 if engine.lower() == "postgres" else 3306))
        preflight_summary["checked"] = [f"direct_db:{engine.lower()}"]
        reach = direct_db_reachability_fn(
            engine=engine, host=host, port=port, timeout=min(timeout_non_web, 5.0)
        )
        reachable = bool(reach.get("reachable"))
        if reachable:
            preflight_summary["executed"] = [f"direct_db:{engine.lower()}"]
        else:
            preflight_summary["ok"] = False
            code = f"direct_db:{engine.lower()}"
            preflight_summary["missing"] = [code]
            preflight_fail_inc_fn(code)
            coverage_ledger.deps_missing = list(dict.fromkeys([*(coverage_ledger.deps_missing or []), code]))
        evidence_lines = [f"{k}={v}" for k, v in reach.items()]
        results.append(
            {
                "vector": f"DIRECT_DB_{engine.upper()}",
                "vulnerable": False,
                "evidence": evidence_lines[:20],
                "exit_code": 0 if reachable else 1,
                "command": [],
                "error": (None if reachable else str(reach.get("detail") or "unreachable")),
            }
        )
        await mark_phase_fn(
            execution_phase,
            f"direct_db_reachability:{'ok' if reachable else 'failed'}",
            status=("completed" if reachable else "failed"),
        )

    elif mode == "ws":
        ws_url = str(omni_cfg.get("wsUrl") or "")
        preflight_summary["checked"] = ["websockets"]
        ws_result = await websocket_exploit_fn(url=ws_url, config=omni_cfg, timeout=timeout_non_web)
        reachable = bool(ws_result.get("reachable"))
        vulnerable = bool(ws_result.get("vulnerable"))
        vulns = ws_result.get("vulnerabilities") if isinstance(ws_result.get("vulnerabilities"), list) else []
        evidence_lines = [str(v) for v in vulns[:20]]
        detail = str(ws_result.get("detail") or "")
        if detail:
            evidence_lines.append(f"detail={detail}")
        if reachable:
            preflight_summary["executed"] = ["websockets"]
        else:
            preflight_summary["ok"] = False
            preflight_summary["missing"] = ["websockets"]
            preflight_fail_inc_fn("websockets")
            coverage_ledger.deps_missing = list(
                dict.fromkeys([*(coverage_ledger.deps_missing or []), "websockets"])
            )
        results.append(
            {
                "vector": "WEBSOCKET",
                "vulnerable": vulnerable,
                "evidence": evidence_lines,
                "exit_code": 0 if reachable else 1,
                "command": [],
                "error": (None if reachable else (detail or "ws_unreachable")),
            }
        )
        final_vuln = bool(final_vuln or vulnerable)
        await mark_phase_fn(
            execution_phase,
            f"ws_probe:{'ok' if reachable else 'failed'}",
            status=("completed" if reachable else "failed"),
        )

    elif mode == "mqtt":
        mqtt_cfg = omni_cfg.get("mqtt", {}) or {}
        host = str(mqtt_cfg.get("host") or "")
        port = int(mqtt_cfg.get("port") or 1883)
        preflight_summary["checked"] = ["paho-mqtt"]
        mqtt_result = await mqtt_exploit_fn(host=host, port=port, timeout=timeout_non_web, config=omni_cfg)
        reachable = bool(mqtt_result.get("reachable"))
        vulnerable = bool(mqtt_result.get("vulnerable"))
        vulns = mqtt_result.get("vulnerabilities") if isinstance(mqtt_result.get("vulnerabilities"), list) else []
        evidence_lines = [str(v) for v in vulns[:20]]
        detail = str(mqtt_result.get("detail") or "")
        if detail:
            evidence_lines.append(f"detail={detail}")
        if reachable:
            preflight_summary["executed"] = ["paho-mqtt"]
        else:
            preflight_summary["ok"] = False
            preflight_summary["missing"] = ["paho-mqtt"]
            preflight_fail_inc_fn("paho-mqtt")
            coverage_ledger.deps_missing = list(
                dict.fromkeys([*(coverage_ledger.deps_missing or []), "paho-mqtt"])
            )
        results.append(
            {
                "vector": "MQTT",
                "vulnerable": vulnerable,
                "evidence": evidence_lines,
                "exit_code": 0 if reachable else 1,
                "command": [],
                "error": (None if reachable else (detail or "mqtt_unreachable")),
            }
        )
        final_vuln = bool(final_vuln or vulnerable)
        await mark_phase_fn(
            execution_phase,
            f"mqtt_probe:{'ok' if reachable else 'failed'}",
            status=("completed" if reachable else "failed"),
        )

    elif mode == "grpc":
        grpc_cfg = omni_cfg.get("grpc", {}) or {}
        host = str(grpc_cfg.get("host") or "")
        port = int(grpc_cfg.get("port") or 50051)
        preflight_summary["checked"] = ["grpcio"]
        grpc_result = await grpc_deep_fuzz_probe_fn(host=host, port=port, timeout=timeout_non_web)
        reachable = bool(grpc_result.get("reachable"))
        vulns = grpc_result.get("vulnerabilities") if isinstance(grpc_result.get("vulnerabilities"), list) else []
        vulnerable = bool(vulns)
        evidence_lines = [str(v) for v in vulns[:20]]
        detail = str(grpc_result.get("detail") or "")
        if detail:
            evidence_lines.append(f"detail={detail}")
        if reachable:
            preflight_summary["executed"] = ["grpcio"]
        else:
            preflight_summary["ok"] = False
            preflight_summary["missing"] = ["grpcio"]
            preflight_fail_inc_fn("grpcio")
            coverage_ledger.deps_missing = list(
                dict.fromkeys([*(coverage_ledger.deps_missing or []), "grpcio"])
            )
        results.append(
            {
                "vector": "GRPC",
                "vulnerable": vulnerable,
                "evidence": evidence_lines,
                "exit_code": 0 if reachable else 1,
                "command": [],
                "error": (None if reachable else (detail or "grpc_unreachable")),
            }
        )
        final_vuln = bool(final_vuln or vulnerable)
        await mark_phase_fn(
            execution_phase,
            f"grpc_probe:{'ok' if reachable else 'failed'}",
            status=("completed" if reachable else "failed"),
        )

    return {
        "results": results,
        "final_vuln": bool(final_vuln),
        "phases_ran": phases_ran,
        "preflight_summary": preflight_summary,
    }
