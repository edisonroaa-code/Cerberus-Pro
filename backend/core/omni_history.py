"""
History artifact helpers for Omni scan persistence.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple


def make_history_paths(
    *,
    scan_id: str,
    target_url: str,
    mode: str,
    history_dir: str,
    target_slug_fn: Callable[[str], str],
    now: Optional[datetime] = None,
) -> Tuple[str, str, str]:
    current = now or datetime.now(timezone.utc)
    timestamp = current.strftime("%Y%m%d_%H%M%S")
    target_clean = target_slug_fn(target_url or mode or "unknown")
    filename = (
        f"scan_{timestamp}_{scan_id}_{target_clean}.json"
        if str(scan_id or "").strip()
        else f"scan_{timestamp}_{target_clean}.json"
    )
    filepath = os.path.join(history_dir, filename)
    return filename, filepath, current.isoformat()


def build_history_data(
    *,
    filename: str,
    timestamp_iso: str,
    target: str,
    mode: str,
    profile: Any,
    vulnerable: bool,
    verdict: str,
    conclusive: bool,
    count: int,
    data: list,
    coverage: dict,
    config: dict,
) -> Dict[str, Any]:
    return {
        "id": filename,
        "timestamp": timestamp_iso,
        "target": target,
        "mode": mode,
        "profile": profile,
        "vulnerable": bool(vulnerable),
        "verdict": verdict,
        "conclusive": bool(conclusive),
        "count": int(count),
        "results_count": int(count),
        "evidence_count": int(0),
        "data": data,
        "coverage": coverage,
        "config": config,
    }


def set_evidence_count(history_data: Dict[str, Any], evidence_count: int) -> None:
    history_data["evidence_count"] = int(max(0, int(evidence_count)))


def persist_history_json(*, filepath: str, filename: str, history_data: Dict[str, Any], store_plain: bool) -> None:
    if store_plain:
        with open(filepath, "w", encoding="utf-8") as handler:
            json.dump(history_data, handler, indent=2, ensure_ascii=False)
        return

    safe_summary = {
        "id": filename,
        "timestamp": history_data.get("timestamp"),
        "target": history_data.get("target"),
        "mode": history_data.get("mode"),
        "profile": history_data.get("profile"),
        "vulnerable": history_data.get("vulnerable"),
        "verdict": history_data.get("verdict"),
        "conclusive": history_data.get("conclusive"),
        "count": history_data.get("count"),
        "encrypted": True,
        "artifact": os.path.basename(filepath).replace(".json", ".enc"),
    }
    with open(filepath, "w", encoding="utf-8") as handler:
        json.dump(safe_summary, handler, indent=2, ensure_ascii=False)


def persist_encrypted_artifact(
    *,
    filepath: str,
    history_data: Dict[str, Any],
    encrypt_report_fn: Callable[[Dict[str, Any], Any], bytes],
    get_encryption_key_fn: Callable[[], Any],
) -> str:
    encrypted_path = filepath.replace(".json", ".enc")
    enc_key = get_encryption_key_fn()
    with open(encrypted_path, "wb") as handler:
        handler.write(encrypt_report_fn(history_data, enc_key))
    return os.path.basename(encrypted_path)
