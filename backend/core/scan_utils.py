"""
Utilities for unified scan configuration/validation and scan artifact helpers.

Kept framework-light to allow reuse from the API runtime without pulling in
stateful dependencies.
"""

from __future__ import annotations

import os
import re
from typing import List, Set
from urllib.parse import urlparse

from fastapi import HTTPException

OMNI_ALLOWED_MODES = {"web", "graphql", "direct_db", "ws", "mqtt", "grpc"}
OMNI_ALLOWED_VECTORS = {"UNION", "ERROR", "TIME", "BOOLEAN", "STACKED", "INLINE", "AIIE"}
AUTOPILOT_MAX_PHASE = 4


def _read_unified_runtime_cfg(cfg: dict) -> dict:
    return dict((cfg or {}).get("unified") or {})


def _ensure_unified_cfg_aliases(cfg: dict) -> dict:
    out = dict(cfg or {})
    unified_cfg = _read_unified_runtime_cfg(out)
    out["unified"] = dict(unified_cfg)
    return out


def _merge_tampers(current: str, incoming: List[str]) -> str:
    existing = [t.strip() for t in (current or "").split(",") if t.strip()]
    merged: List[str] = []
    for t in existing + incoming:
        if t and t not in merged:
            merged.append(t)
    return ",".join(merged)


def _autopilot_difficulty(cfg: dict) -> str:
    level = int(cfg.get("aggressionLevel") or 5)
    profile = str(cfg.get("profile") or "").lower()
    if "agresiva" in profile or level >= 9:
        return "extreme"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _apply_autopilot_policy(cfg: dict, mode: str, phase: int = 1) -> dict:
    out = dict(cfg or {})
    sql_cfg = dict(out.get("sqlMap", {}) or {})
    omni_cfg = _read_unified_runtime_cfg(out)
    difficulty = _autopilot_difficulty(out)
    p = max(1, min(int(phase), AUTOPILOT_MAX_PHASE))

    base = {
        "low": {"threads": 3, "level": 2, "risk": 1, "delay": 2.0, "tampers": ["space2comment"]},
        "medium": {"threads": 5, "level": 3, "risk": 2, "delay": 1.0, "tampers": ["space2comment", "between"]},
        "high": {"threads": 7, "level": 4, "risk": 2, "delay": 0.6, "tampers": ["space2comment", "between", "randomcase"]},
        "extreme": {"threads": 10, "level": 5, "risk": 3, "delay": 0.2, "tampers": ["space2comment", "randomcase", "charencode", "base64encode"]},
    }[difficulty]
    threads = min(10, int(base["threads"]) + (p - 1))
    level = min(5, int(base["level"]) + (1 if p >= 3 else 0))
    risk = min(3, int(base["risk"]) + (1 if p >= 4 else 0))
    delay = max(0.0, float(base["delay"]) - (0.15 * (p - 1)))

    sql_cfg["threads"] = max(int(sql_cfg.get("threads") or 0), threads)
    sql_cfg["level"] = max(int(sql_cfg.get("level") or 0), level)
    sql_cfg["risk"] = max(int(sql_cfg.get("risk") or 0), risk)
    sql_cfg["tamper"] = _merge_tampers(str(sql_cfg.get("tamper") or ""), list(base["tampers"]))
    sql_cfg["auto_delay"] = round(delay, 2)
    sql_cfg["timeout"] = int(sql_cfg.get("timeout") or 15)
    sql_cfg["randomAgent"] = True
    out["sqlMap"] = sql_cfg
    out["autoPilotPhase"] = p
    out["autoPilotDifficulty"] = difficulty

    if mode in ("web", "graphql"):
        vectors = list(omni_cfg.get("vectors") or ["UNION", "ERROR", "TIME", "BOOLEAN"])
        if p >= 2 and "STACKED" not in vectors:
            vectors.append("STACKED")
        if p >= 3 and "INLINE" not in vectors:
            vectors.append("INLINE")
        omni_cfg["vectors"] = [v for v in vectors if v in OMNI_ALLOWED_VECTORS]
        omni_cfg["maxParallel"] = min(8, max(int(omni_cfg.get("maxParallel") or 2), 2 + p))
        if p >= 3:
            omni_cfg.setdefault("noSql", True)
            omni_cfg.setdefault("ssti", True)
        if p >= 4:
            omni_cfg.setdefault("chaining", True)
        if mode == "graphql":
            omni_cfg.setdefault("profile", "json_hpp_aggressive")
    else:
        omni_cfg["maxParallel"] = min(8, max(int(omni_cfg.get("maxParallel") or 1), 1 + (p // 2)))
        if p >= 3:
            omni_cfg.setdefault("deepFuzz", True)
    out["unified"] = dict(omni_cfg)
    return out


def _validate_host_port(host: str, port: int, label: str):
    if not host or not str(host).strip():
        raise HTTPException(status_code=400, detail=f"{label}: host requerido")
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail=f"{label}: puerto inválido")


def validate_omni_config(
    cfg: dict,
    *,
    allowed_modes: Set[str] = OMNI_ALLOWED_MODES,
    allowed_vectors: Set[str] = OMNI_ALLOWED_VECTORS,
):
    raw_cfg = dict(cfg or {})
    if "unified" not in raw_cfg and "omni" in raw_cfg:
        raise HTTPException(status_code=400, detail="Contrato legado detectado: usa config.unified (config.omni removido)")
    cfg = _ensure_unified_cfg_aliases(raw_cfg)
    mode = (cfg.get("mode") or "web").lower()
    if mode not in allowed_modes:
        raise HTTPException(status_code=400, detail=f"Modo Omni inválido: {mode}")

    unified_cfg = _read_unified_runtime_cfg(cfg)
    max_parallel = int(unified_cfg.get("maxParallel", 4))
    if max_parallel < 1 or max_parallel > 8:
        raise HTTPException(status_code=400, detail="maxParallel fuera de rango (1-8)")

    vectors = unified_cfg.get("vectors", [])
    if mode in ("web", "graphql"):
        if not isinstance(vectors, list) or not vectors:
            raise HTTPException(status_code=400, detail="Se requiere al menos un vector")
        if any(v not in allowed_vectors for v in vectors):
            raise HTTPException(status_code=400, detail="Lista de vectores inválida")

    if mode == "graphql":
        gql = unified_cfg.get("graphqlQuery")
        if not gql or not isinstance(gql, str):
            raise HTTPException(status_code=400, detail="GraphQL query requerida")

    if mode == "direct_db":
        db_cfg = unified_cfg.get("directDb", {}) or {}
        _validate_host_port(str(db_cfg.get("host", "")), int(db_cfg.get("port", 0)), "direct_db")

    if mode == "ws":
        ws_url = str(unified_cfg.get("wsUrl", ""))
        if not (ws_url.startswith("ws://") or ws_url.startswith("wss://")):
            raise HTTPException(status_code=400, detail="wsUrl inválida")

    if mode == "mqtt":
        mqtt_cfg = unified_cfg.get("mqtt", {}) or {}
        _validate_host_port(str(mqtt_cfg.get("host", "")), int(mqtt_cfg.get("port", 0)), "mqtt")

    if mode == "grpc":
        grpc_cfg = unified_cfg.get("grpc", {}) or {}
        _validate_host_port(str(grpc_cfg.get("host", "")), int(grpc_cfg.get("port", 0)), "grpc")

    if unified_cfg.get("oob"):
        oob = unified_cfg["oob"]
        if oob.get("dnsDomain") and not isinstance(oob["dnsDomain"], str):
            raise HTTPException(status_code=400, detail="dnsDomain debe ser un string")
        if oob.get("icmp") and not isinstance(oob["icmp"], bool):
            raise HTTPException(status_code=400, detail="icmp debe ser un booleano")

    if unified_cfg.get("pivoting"):
        piv = unified_cfg["pivoting"]
        if piv.get("proxy") and not isinstance(piv["proxy"], str):
            raise HTTPException(status_code=400, detail="proxy debe ser un string (e.g. socks5://127.0.0.1:9050)")
        if piv.get("tor") and not isinstance(piv["tor"], bool):
            raise HTTPException(status_code=400, detail="tor debe ser un booleano")

    return mode


def _default_unified_vectors_from_cfg(
    cfg: dict, *, allowed_vectors: Set[str] = OMNI_ALLOWED_VECTORS
) -> List[str]:
    sql_cfg = (cfg.get("sqlMap", {}) or {})
    technique = str(sql_cfg.get("technique") or "BEUSTQ").upper()
    mapping = {
        "B": "BOOLEAN",
        "E": "ERROR",
        "U": "UNION",
        "S": "STACKED",
        "T": "TIME",
        "Q": "INLINE",
    }
    vectors: List[str] = []
    for key, vec in mapping.items():
        if key in technique and vec in allowed_vectors and vec not in vectors:
            vectors.append(vec)
    if not vectors:
        vectors = ["UNION", "ERROR", "TIME", "BOOLEAN"]
    return vectors


def _normalize_unified_scan_cfg(
    raw_cfg: dict, *, allowed_vectors: Set[str] = OMNI_ALLOWED_VECTORS
) -> dict:
    cfg = dict(raw_cfg or {})
    mode = str(cfg.get("mode") or "web").lower().strip() or "web"
    cfg["mode"] = mode

    unified_cfg = _read_unified_runtime_cfg(cfg)
    if mode in ("web", "graphql"):
        raw_vectors = unified_cfg.get("vectors")
        if isinstance(raw_vectors, list) and raw_vectors:
            vectors = [str(v).upper() for v in raw_vectors if str(v).upper() in allowed_vectors]
        else:
            vectors = _default_unified_vectors_from_cfg(cfg, allowed_vectors=allowed_vectors)
        unified_cfg["vectors"] = vectors
        unified_cfg["maxParallel"] = int(unified_cfg.get("maxParallel") or 4)
        if mode == "graphql" and not unified_cfg.get("graphqlQuery"):
            unified_cfg["graphqlQuery"] = "query { __typename }"
    else:
        unified_cfg["maxParallel"] = int(unified_cfg.get("maxParallel") or 2)

    cfg["unified"] = dict(unified_cfg)
    return cfg


def _target_slug(url: str) -> str:
    try:
        p = urlparse(url)
        raw = f"{p.hostname or 'unknown'}_{p.port or ''}{p.path or ''}"
    except Exception:
        raw = url
    raw = raw.encode("ascii", "ignore").decode("ascii")
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    return (raw or "unknown")[:40]


def _safe_history_path(history_dir: str, filename: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.json", filename):
        raise HTTPException(status_code=400, detail="Nombre de archivo inválido")
    base = os.path.realpath(history_dir)
    candidate = os.path.realpath(os.path.join(base, filename))
    if not candidate.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="Ruta de historial inválida")
    return candidate

