"""
Coverage API model mappers extracted from ares_api.py.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.coverage_contract_v1 import (
    CoveragePhaseRecordV1,
    CoverageResponseV1,
    CoverageVectorRecordV1,
    VectorRecordsPageV1,
)


def _build_default_vector_page(limit: int = 50, cursor: int = 0) -> VectorRecordsPageV1:
    lim = max(1, min(int(limit), 500))
    cur = max(0, int(cursor))
    return VectorRecordsPageV1(limit=lim, cursor=cur, next_cursor=None, has_more=False, items=[])


def _safe_phase_status(raw_status: Any) -> str:
    status_value = str(raw_status or "").strip().lower()
    if status_value in {"completed", "partial", "failed", "timeout"}:
        return status_value
    if status_value == "partially_completed":
        return "partial"
    return "completed" if status_value else "partial"


def _safe_phase_notes(notes: Any) -> List[str]:
    if not isinstance(notes, list):
        return []
    out: List[str] = []
    for note in notes[:20]:
        text = str(note or "").strip()
        if text:
            out.append(text)
    return out


def _to_phase_records_v1(records: Optional[List[Any]]) -> List[CoveragePhaseRecordV1]:
    out: List[CoveragePhaseRecordV1] = []
    for rec in records or []:
        if rec is None:
            continue
        try:
            phase = str(getattr(rec, "phase", "") or (rec.get("phase") if isinstance(rec, dict) else "")).strip()
        except Exception:
            phase = ""
        if not phase:
            continue
        duration = getattr(rec, "duration_ms", None) if not isinstance(rec, dict) else rec.get("duration_ms")
        items_processed = getattr(rec, "items_processed", None) if not isinstance(rec, dict) else rec.get("items_processed")
        items_failed = getattr(rec, "items_failed", None) if not isinstance(rec, dict) else rec.get("items_failed")
        notes = getattr(rec, "notes", None) if not isinstance(rec, dict) else rec.get("notes")
        start_time = getattr(rec, "start_time", None) if not isinstance(rec, dict) else rec.get("start_time")
        end_time = getattr(rec, "end_time", None) if not isinstance(rec, dict) else rec.get("end_time")
        status = getattr(rec, "status", None) if not isinstance(rec, dict) else rec.get("status")

        out.append(
            CoveragePhaseRecordV1(
                phase=phase,
                status=_safe_phase_status(status),
                duration_ms=max(0, int(duration or 0)),
                items_processed=max(0, int(items_processed or 0)),
                items_failed=max(0, int(items_failed or 0)),
                notes=_safe_phase_notes(notes),
                started_at=(
                    start_time.isoformat()
                    if hasattr(start_time, "isoformat")
                    else (str(start_time) if start_time else None)
                ),
                ended_at=(
                    end_time.isoformat()
                    if hasattr(end_time, "isoformat")
                    else (str(end_time) if end_time else None)
                ),
            )
        )
    return out


def _to_vector_records_v1(records: Optional[List[Any]]) -> List[CoverageVectorRecordV1]:
    out: List[CoverageVectorRecordV1] = []
    for rec in records or []:
        if rec is None:
            continue
        rec_dict: Dict[str, Any]
        if isinstance(rec, dict):
            rec_dict = rec
        else:
            rec_dict = {
                "vector_id": getattr(rec, "vector_id", None),
                "vector_name": getattr(rec, "vector_name", None),
                "engine": getattr(rec, "engine", None),
                "status": getattr(rec, "status", None),
                "inputs_tested": getattr(rec, "inputs_tested", 0),
                "duration_ms": getattr(rec, "duration_ms", 0),
                "error": getattr(rec, "error", None),
            }
        vector_id = str(rec_dict.get("vector_id") or "").strip()
        vector_name = str(rec_dict.get("vector_name") or "").strip()
        engine = str(rec_dict.get("engine") or "").strip()
        if not vector_id:
            vector_id = f"{engine or 'engine'}:{vector_name or 'vector'}"
        if not vector_name:
            vector_name = vector_id
        if not engine:
            engine = "unknown"
        raw_status = rec_dict.get("status")
        if hasattr(raw_status, "value"):
            status = str(getattr(raw_status, "value") or "PENDING").upper()
        else:
            status = str(raw_status or "PENDING").upper()
            if status.startswith("COVERAGESTATUS."):
                status = status.split(".", 1)[1]
        if status not in {"EXECUTED", "QUEUED", "FAILED", "SKIPPED", "PENDING", "TIMEOUT"}:
            status = "PENDING"
        out.append(
            CoverageVectorRecordV1(
                vector_id=vector_id,
                vector_name=vector_name,
                engine=engine,
                status=status,
                inputs_tested=max(0, int(rec_dict.get("inputs_tested") or 0)),
                duration_ms=max(0, int(rec_dict.get("duration_ms") or 0)),
                error=(str(rec_dict.get("error")) if rec_dict.get("error") else None),
            )
        )
    return out


def _coverage_public_payload(
    response: CoverageResponseV1, *, legacy_reason_codes: Optional[List[str]] = None
) -> Dict[str, Any]:
    payload = response.model_dump()
    payload["schema_version"] = response.version
    payload["legacy_reason_codes"] = legacy_reason_codes or []
    return payload
