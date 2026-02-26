"""
Runtime helpers for Omni scan orchestration extracted from ares_api.py.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import parse_qs, urlparse


def prepare_omni_scan_context(
    *,
    cfg: dict,
    user_id: str,
    state_omni_meta: dict,
    allowed_vectors: Set[str],
) -> Dict[str, Any]:
    target_url = cfg.get("url", "")
    sql_config = cfg.get("sqlMap", {})
    mode = (cfg.get("mode") or "web").lower()
    omni_cfg = dict((cfg or {}).get("unified") or {})
    vectors = omni_cfg.get("vectors") or ["UNION", "ERROR", "TIME", "BOOLEAN"]
    max_parallel = int(omni_cfg.get("maxParallel", 4))
    engine_scan_enabled = bool(
        omni_cfg.get("engine_scan") or omni_cfg.get("engineScan") or omni_cfg.get("engines")
    )
    configured_engine_list = [
        str(engine).strip().lower()
        for engine in (omni_cfg.get("engines") or [])
        if str(engine).strip()
    ]
    is_deep = bool(omni_cfg.get("deep_audit"))
    phases = [1, 3, 5] if is_deep else [int(cfg.get("autoPilotPhase") or 1)]
    strict_conclusive = omni_cfg.get("strict_conclusive", omni_cfg.get("strictConclusive", True))
    strict_conclusive = True if strict_conclusive is None else bool(strict_conclusive)
    defended_by_default = bool(omni_cfg.get("defendedByDefault", True))
    requested_sqlmap_vectors = [
        str(vec).upper() for vec in (vectors or []) if str(vec).upper() in allowed_vectors
    ]
    scan_id = str((state_omni_meta.get(user_id) or {}).get("scan_id") or f"omni_{user_id}")
    return {
        "target_url": target_url,
        "sql_config": sql_config,
        "mode": mode,
        "omni_cfg": omni_cfg,
        "vectors": vectors,
        "max_parallel": max_parallel,
        "engine_scan_enabled": engine_scan_enabled,
        "configured_engine_list": configured_engine_list,
        "is_deep": is_deep,
        "phases": phases,
        "strict_conclusive": strict_conclusive,
        "defended_by_default": defended_by_default,
        "requested_sqlmap_vectors": requested_sqlmap_vectors,
        "scan_id": scan_id,
        "scan_started_at": datetime.now(timezone.utc),
    }


def compute_defended_heuristics_seed(
    *,
    mode: str,
    target_url: str,
    defended_by_default: bool,
    omni_cfg: dict,
) -> Dict[str, Any]:
    defended_heuristics: Dict[str, Any] = {"suspected": False, "reasons": []}
    if mode not in ("web", "graphql") or (not defended_by_default):
        return defended_heuristics

    parsed_target = urlparse(str(target_url or ""))
    query_keys = [
        str(key).strip()
        for key in parse_qs(parsed_target.query, keep_blank_values=True).keys()
        if str(key).strip()
    ]
    raw_cfg_params = omni_cfg.get("parameters", omni_cfg.get("params", []))
    if isinstance(raw_cfg_params, str):
        cfg_params = [p.strip() for p in raw_cfg_params.split(",") if p.strip()]
    elif isinstance(raw_cfg_params, list):
        cfg_params = [str(p).strip() for p in raw_cfg_params if str(p).strip()]
    else:
        cfg_params = []
    if (not query_keys) and (not cfg_params):
        defended_heuristics["suspected"] = True
        defended_heuristics["reasons"] = list(
            dict.fromkeys([*(defended_heuristics.get("reasons") or []), "no_explicit_parameters"])
        )
    return defended_heuristics


def merge_defended_heuristics(base: Dict[str, Any], http_heuristics: Dict[str, Any]) -> Dict[str, Any]:
    merged_reasons = list(
        dict.fromkeys([*(base.get("reasons") or []), *((http_heuristics or {}).get("reasons") or [])])
    )
    return {
        "suspected": bool(base.get("suspected") or bool((http_heuristics or {}).get("suspected"))),
        "reasons": merged_reasons,
    }


def build_requested_engines(
    *,
    mode: str,
    requested_sqlmap_vectors: Sequence[str],
    omni_cfg: dict,
    engine_scan_enabled: bool,
    configured_engine_list: Sequence[str],
) -> List[str]:
    requested_engines: List[str] = []
    if mode in ("web", "graphql"):
        requested_engines.extend([str(v).upper() for v in requested_sqlmap_vectors])
        if omni_cfg.get("noSql"):
            requested_engines.append("NOSQL")
        if omni_cfg.get("ssti"):
            requested_engines.append("SSTI")
        if ("AIIE" in requested_sqlmap_vectors) or omni_cfg.get("aiie"):
            requested_engines.append("AIIE")
        if engine_scan_enabled:
            selected = configured_engine_list or [
                "sqlmap",
                "zap",
                "nmap",
                "custom_payload",
                "advanced_payload",
                "burp",
            ]
            requested_engines.extend([f"ENGINE_{str(engine).upper()}" for engine in selected])
    elif mode == "direct_db":
        db_engine = str(((omni_cfg.get("directDb") or {}).get("engine") or "mysql")).upper()
        requested_engines.append(f"DIRECT_DB_{db_engine}")
    elif mode == "ws":
        requested_engines.append("WEBSOCKET")
    elif mode == "mqtt":
        requested_engines.append("MQTT")
    elif mode == "grpc":
        requested_engines.append("GRPC")
    else:
        requested_engines.append(mode.upper())

    deduped_requested_engines: List[str] = []
    for engine in requested_engines:
        name = str(engine or "").strip().upper()
        if name and name not in deduped_requested_engines:
            deduped_requested_engines.append(name)
    return deduped_requested_engines


def build_engine_vectors_for_target(target_url: str, omni_cfg: dict) -> List[Dict[str, Any]]:
    parsed = urlparse(target_url or "")
    endpoint = parsed.path or "/"
    query_params = list((parse_qs(parsed.query, keep_blank_values=True) or {}).keys())

    configured_params = omni_cfg.get("parameters", omni_cfg.get("params", []))
    if not isinstance(configured_params, list):
        configured_params = []
    configured_params = [str(param).strip() for param in configured_params if str(param).strip()]

    header_params = ["User-Agent", "Referer", "Host"]
    all_params: List[str] = []
    for param in [*query_params, *configured_params, *header_params]:
        if param and param not in all_params:
            all_params.append(param)
    if not all_params:
        all_params = ["id"]

    return [
        {
            "endpoint": endpoint,
            "parameter": param,
            "method": "GET",
            "payloads": [],
        }
        for param in all_params
    ]


def extract_runtime_signals(evidence_lines: List[str]) -> Set[str]:
    signals: Set[str] = set()
    for line in evidence_lines or []:
        if not isinstance(line, str):
            continue
        if line.startswith("runtime_signal:"):
            marker = line.split("runtime_signal:", 1)[1].strip().lower()
            if marker:
                signals.add(marker)
    return signals


def analyze_omni_results_for_verdict(
    *,
    results: List[Dict[str, Any]],
    requested_sqlmap_vectors: Sequence[str],
    omni_allowed_vectors: Set[str],
    mode: str,
    target_url: str,
    omni_cfg: dict,
    final_vuln: bool,
    strict_conclusive: bool,
    is_deep: bool,
    phases_ran: Sequence[int],
    phases: Sequence[int],
    waf_preset_last: Optional[str],
    bypass_attempted: bool,
    bypass_cookie_obtained: bool,
    coverage_deps_missing: Sequence[str],
) -> Dict[str, Any]:
    results_count = len(results)
    evidence_count = 0
    failed_vectors: List[str] = []
    missing_deps: List[str] = []
    exception_count = 0

    for result in results:
        if not isinstance(result, dict):
            continue
        evidence = result.get("evidence")
        if isinstance(evidence, list):
            evidence_count += len(evidence)
            for line in evidence:
                if isinstance(line, str) and line.lower().startswith("missing "):
                    missing_deps.append(str(result.get("vector") or "unknown"))
                    break
        if result.get("error"):
            exception_count += 1
        exit_code = result.get("exit_code")
        if isinstance(exit_code, int) and exit_code != 0:
            failed_vectors.append(str(result.get("vector") or "unknown"))

    present_vectors = {str(result.get("vector") or "").upper() for result in results if isinstance(result, dict)}
    missing_requested = [vec for vec in requested_sqlmap_vectors if str(vec).upper() not in present_vectors]

    sqlmap_tested_params: Set[str] = set()
    sqlmap_no_forms_found = False
    sqlmap_missing_parameters = False
    sqlmap_explicit_not_injectable = False

    def _safe_exit_code(value: Any) -> int:
        try:
            return int(value)
        except Exception:
            return 1

    try:
        for result in results:
            if not isinstance(result, dict):
                continue
            vector = str(result.get("vector") or "")
            if vector.upper() not in omni_allowed_vectors:
                continue
            evidence = result.get("evidence")
            if not isinstance(evidence, list):
                continue
            for line in evidence:
                if not isinstance(line, str):
                    continue
                low = line.lower()
                if (
                    ("no forms found" in low)
                    or ("no forms were found" in low)
                    or ("no se encontraron formularios" in low)
                    or ("no se encontraron forms" in low)
                ):
                    sqlmap_no_forms_found = True
                if ("you must provide at least one parameter" in low) or (
                    "debes proporcionar al menos un parámetro" in low
                ) or ("debes proporcionar al menos un parametro" in low):
                    sqlmap_missing_parameters = True
                if (
                    (("all tested parameters do not appear" in low) and ("injectable" in low))
                    or ("todos los parámetros probados no parecen ser inyectables" in low)
                    or ("todos los parametros probados no parecen ser inyectables" in low)
                ):
                    sqlmap_explicit_not_injectable = True
                for match in re.finditer(
                    r"(?i)\b(?:parameter|par[aá]metro):\s*([a-z0-9_\-]+)\s*\((?:get|post|uri|cookie|header)\)",
                    line,
                ):
                    sqlmap_tested_params.add(match.group(1))
                for match in re.finditer(
                    r"(?i)\b(?:get|post|uri|cookie|header)\s+parameter\s+['\"]([^'\"]+)['\"]",
                    line,
                ):
                    sqlmap_tested_params.add(match.group(1))
                for match in re.finditer(r"(?i)\b(?:parameter|par[aá]metro)\s+['\"]([^'\"]+)['\"]", line):
                    sqlmap_tested_params.add(match.group(1))
                for match in re.finditer(r"(?i)\btested_parameter:([a-z0-9_\\-]+)\b", line):
                    sqlmap_tested_params.add(match.group(1))
    except Exception:
        sqlmap_tested_params = set()

    if (mode in ("web", "graphql")) and (not sqlmap_tested_params):
        parsed_target = urlparse(target_url or "")
        query_keys = [
            str(key).strip()
            for key in parse_qs(parsed_target.query, keep_blank_values=True).keys()
            if str(key).strip()
        ]
        configured_params = omni_cfg.get("parameters", omni_cfg.get("params", []))
        if not isinstance(configured_params, list):
            configured_params = []
        configured_keys = [str(param).strip() for param in configured_params if str(param).strip()]
        candidate_params: List[str] = []
        for param in [*query_keys, *configured_keys]:
            if param and param not in candidate_params:
                candidate_params.append(param)

        sqlmap_success_vectors = {
            str(result.get("vector") or "").upper()
            for result in results
            if isinstance(result, dict)
            and str(result.get("vector") or "").upper() in {str(v).upper() for v in requested_sqlmap_vectors}
            and _safe_exit_code(result.get("exit_code")) == 0
        }
        if candidate_params and sqlmap_success_vectors:
            sqlmap_tested_params.update(candidate_params)

    inputs_tested = (len(sqlmap_tested_params) > 0) or bool(sqlmap_explicit_not_injectable)
    reasons: List[str] = []

    def _add_reason(reason_code: str) -> None:
        code = str(reason_code or "").strip()
        if code and code not in reasons:
            reasons.append(code)

    merged_missing_deps = sorted(list(set([*list(coverage_deps_missing or []), *missing_deps])))
    if results_count == 0:
        _add_reason("no_results")
    if missing_requested:
        _add_reason("missing_vectors:" + ",".join(missing_requested[:8]))
    if failed_vectors:
        requested_set = {str(v).upper() for v in requested_sqlmap_vectors}
        failed_set = {str(v).upper() for v in failed_vectors}
        successful_set = {
            str(result.get("vector") or "").upper()
            for result in results
            if isinstance(result, dict) and _safe_exit_code(result.get("exit_code")) == 0
        }
        requested_success = requested_set.intersection(successful_set)
        requested_failed = requested_set.intersection(failed_set)
        if requested_set and (len(requested_success) == 0) and requested_failed:
            _add_reason("vector_failures:" + ",".join(sorted(requested_failed)[:8]))
    if exception_count:
        _add_reason("engine_errors")
    if merged_missing_deps:
        _add_reason("missing_dependencies:" + ",".join(merged_missing_deps[:8]))
    if (mode in ("web", "graphql")) and (not final_vuln) and (not inputs_tested):
        if sqlmap_no_forms_found:
            _add_reason("no_forms_found")
        elif sqlmap_missing_parameters:
            _add_reason("missing_parameters")
        else:
            _add_reason("no_parameters_tested")
    if strict_conclusive and waf_preset_last and bypass_attempted and (not bypass_cookie_obtained):
        _add_reason("waf_bypass_unconfirmed")
    if strict_conclusive and is_deep and (len(phases_ran) != len(phases)):
        _add_reason("phases_incomplete")

    return {
        "results_count": results_count,
        "evidence_count": evidence_count,
        "failed_vectors": failed_vectors,
        "missing_deps": missing_deps,
        "exception_count": exception_count,
        "present_vectors": present_vectors,
        "missing_requested": missing_requested,
        "sqlmap_tested_params": sqlmap_tested_params,
        "sqlmap_no_forms_found": sqlmap_no_forms_found,
        "sqlmap_missing_parameters": sqlmap_missing_parameters,
        "sqlmap_explicit_not_injectable": sqlmap_explicit_not_injectable,
        "inputs_tested": inputs_tested,
        "reasons": reasons,
        "merged_missing_deps": merged_missing_deps,
    }


def omni_reason_human(code: str) -> str:
    if code == "no_results":
        return "no se ejecutaron motores"
    if code.startswith("missing_vectors:"):
        return "vectores no ejecutados"
    if code.startswith("vector_failures:"):
        return "fallas/timeout en vectores"
    if code == "engine_errors":
        return "errores internos durante la ejecución"
    if code.startswith("missing_dependencies:"):
        return "dependencias faltantes"
    if code.startswith("missing_deps:"):
        return "dependencias faltantes en preflight"
    if code.startswith("missing_engine:"):
        return "motor requerido sin prerequisitos"
    if code == "no_forms_found":
        return "no se encontraron formularios/inputs para probar"
    if code == "missing_parameters":
        return "faltan parámetros para probar"
    if code == "no_parameters_tested":
        return "no se detectaron parámetros probables para testear"
    if code == "waf_bypass_unconfirmed":
        return "WAF detectado, pero no se confirmó sesión (cookies)"
    if code == "phases_incomplete":
        return "no se completaron todas las fases"
    return str(code)
