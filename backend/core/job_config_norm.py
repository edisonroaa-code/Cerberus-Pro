"""
Job configuration normalization helpers extracted from ares_api.py.
"""

from __future__ import annotations

from typing import Any, Dict

from core.scan_utils import _ensure_unified_cfg_aliases, _read_unified_runtime_cfg


def normalize_classic_to_unified_cfg(cfg: Dict[str, Any]) -> dict:
    normalized = dict(cfg or {})
    sql_cfg = dict(normalized.get("sqlMap") or {})
    normalized["sqlMap"] = sql_cfg

    technique_map = {
        "B": "BOOLEAN",
        "E": "ERROR",
        "T": "TIME",
        "U": "UNION",
        "S": "STACKED",
        "Q": "INLINE",
    }
    technique_raw = str(sql_cfg.get("technique") or "").upper().strip()
    vectors = []
    if technique_raw:
        for letter in technique_raw:
            mapped = technique_map.get(letter)
            if mapped and mapped not in vectors:
                vectors.append(mapped)
    if not vectors:
        vectors = ["BOOLEAN", "ERROR", "TIME", "UNION"]

    unified_cfg = _read_unified_runtime_cfg(normalized)
    unified_cfg.setdefault("vectors", vectors)
    unified_cfg.setdefault("maxParallel", int(sql_cfg.get("threads") or 3))
    # Keep classic behavior close to SQLMap-only execution unless explicitly enabled.
    unified_cfg.setdefault("engine_scan", False)
    normalized["unified"] = dict(unified_cfg)
    normalized["mode"] = "web"
    normalized["_unified_source"] = "classic"
    return normalized


def normalize_unified_job_cfg(kind: str, cfg: Dict[str, Any], canonical_job_kind: str) -> dict:
    source_kind = str(kind or "").strip().lower()
    if source_kind == "classic":
        return normalize_classic_to_unified_cfg(cfg)

    normalized = dict(cfg or {})
    normalized["mode"] = str((normalized.get("mode") or "web")).lower()
    normalized["_unified_source"] = source_kind or str(canonical_job_kind or "unified")
    return _ensure_unified_cfg_aliases(normalized)
