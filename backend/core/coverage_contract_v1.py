"""
Coverage/Report contract v1.

Single contract used across backend persistence/API/frontend ingestion.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple
import json
import re

from pydantic import BaseModel, Field


COVERAGE_SCHEMA_VERSION_V1 = "coverage.v1"
VerdictValue = Literal["VULNERABLE", "NO_VULNERABLE", "INCONCLUSIVE"]


BLOCKER_MESSAGE_BY_CODE: Dict[str, str] = {
    "missing_deps": "Dependencia requerida no disponible",
    "missing_dependencies": "Dependencias faltantes para cobertura completa",
    "missing_engine": "Motor requerido no pudo ejecutarse",
    "engines_incomplete": "No se ejecutaron todos los motores requeridos",
    "inputs_not_tested": "No se probaron inputs/parámetros de forma concluyente",
    "no_forms_found": "No se encontraron formularios/inputs para probar",
    "missing_parameters": "No se detectaron parámetros válidos para probar",
    "no_parameters_tested": "No se detectaron parámetros probables para testear",
    "coverage_incomplete": "Cobertura crítica incompleta",
    "coverage_gaps": "Existen huecos de cobertura",
    "resource_exhausted_incomplete": "Recursos agotados antes de completar cobertura",
    "engine_errors": "Errores internos durante la ejecución",
    "vector_failures": "Fallas o timeout en vectores",
    "missing_vectors": "Vectores requeridos no ejecutados",
    "waf_bypass_unconfirmed": "WAF detectado sin bypass confirmado",
    "phases_incomplete": "No se completaron todas las fases",
    "autopilot_not_exhausted": "Auto-Pilot no agotó fases configuradas",
    "engine_exit_code": "Motor terminó con código de salida no exitoso",
    "legacy_blocker": "Bloqueador legado normalizado",
    "invalid_contract": "Contrato de cobertura inválido",
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return str(value)


def _normalize_code(code: str) -> str:
    c = str(code or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not c:
        return "legacy_blocker"
    return c


def _human_message_for_code(code: str, fallback: str = "") -> str:
    normalized = _normalize_code(code)
    return BLOCKER_MESSAGE_BY_CODE.get(normalized, fallback or normalized)


def _parse_legacy_reason(reason: str) -> Tuple[str, Any]:
    raw = str(reason or "").strip()
    if not raw:
        return ("legacy_blocker", {"raw": raw})

    if raw.startswith("[") and "]" in raw:
        # Pattern from verdict_engine: "[category] detail"
        try:
            category, detail = raw.split("]", 1)
            code = _normalize_code(category.lstrip("["))
            return (code, {"raw": raw, "detail": detail.strip()})
        except Exception:
            return ("legacy_blocker", {"raw": raw})

    if ":" in raw:
        prefix, tail = raw.split(":", 1)
        return (_normalize_code(prefix), {"raw": raw, "detail": tail.strip()})

    if "engine_exit_code" in raw:
        m = re.search(r"engine_exit_code[:=]\s*([0-9-]+)", raw)
        if m:
            return ("engine_exit_code", {"raw": raw, "exit_code": int(m.group(1))})
        return ("engine_exit_code", {"raw": raw})

    return (_normalize_code(raw), {"raw": raw})


SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "set_cookie",
)

SENSITIVE_REGEXES = (
    re.compile(r"(?i)(token|password|secret|api[_-]?key)=([^&\s]+)"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)(cookie:\s*)[^\r\n]+"),
)


def scrub_sensitive_payload(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            low = key.lower()
            if any(part in low for part in SENSITIVE_KEY_PARTS):
                out[key] = "***REDACTED***"
            else:
                out[key] = scrub_sensitive_payload(v)
        return out
    if isinstance(value, list):
        return [scrub_sensitive_payload(v) for v in value]
    if isinstance(value, str):
        text = value
        for rgx in SENSITIVE_REGEXES:
            text = rgx.sub(r"\1***REDACTED***", text)
        return text
    return value


class ConclusiveBlockerV1(BaseModel):
    code: str
    message: str
    detail: Optional[Any] = None
    phase: Optional[str] = None
    recoverable: Optional[bool] = None


class CoverageSummaryV1(BaseModel):
    coverage_percentage: float = 0.0
    engines_requested: List[str] = Field(default_factory=list)
    engines_executed: List[str] = Field(default_factory=list)
    inputs_found: int = 0
    inputs_tested: int = 0
    inputs_failed: int = 0
    deps_missing: List[str] = Field(default_factory=list)
    preflight_ok: bool = False
    execution_ok: bool = False
    verdict_phase_completed: bool = False
    status: str = "in_progress"
    total_duration_ms: int = 0
    redactions_applied: bool = True


class CoveragePhaseRecordV1(BaseModel):
    phase: str
    status: str
    duration_ms: int = 0
    items_processed: int = 0
    items_failed: int = 0
    notes: List[str] = Field(default_factory=list)
    started_at: Optional[str] = None
    ended_at: Optional[str] = None


class CoverageVectorRecordV1(BaseModel):
    id: Optional[int] = None
    vector_id: str
    vector_name: str
    engine: str
    status: str
    inputs_tested: int = 0
    duration_ms: int = 0
    error: Optional[str] = None


class VectorRecordsPageV1(BaseModel):
    limit: int
    cursor: int
    next_cursor: Optional[int] = None
    has_more: bool = False
    items: List[CoverageVectorRecordV1] = Field(default_factory=list)


class CoverageResponseV1(BaseModel):
    version: Literal["coverage.v1"] = COVERAGE_SCHEMA_VERSION_V1
    scan_id: str
    job_status: str
    verdict: VerdictValue
    conclusive: bool
    vulnerable: bool
    coverage_summary: CoverageSummaryV1
    conclusive_blockers: List[ConclusiveBlockerV1] = Field(default_factory=list)
    phase_records: List[CoveragePhaseRecordV1] = Field(default_factory=list)
    vector_records_page: VectorRecordsPageV1
    generated_at: str = Field(default_factory=_utcnow_iso)


class VerdictDecisionV1(BaseModel):
    verdict: VerdictValue
    conclusive: bool
    vulnerable: bool
    blockers: List[ConclusiveBlockerV1] = Field(default_factory=list)


def adapt_legacy_blockers(
    blockers: Optional[List[Any]],
    *,
    default_phase: Optional[str] = None,
) -> List[ConclusiveBlockerV1]:
    out: List[ConclusiveBlockerV1] = []
    seen: set = set()

    for entry in blockers or []:
        blocker: Optional[ConclusiveBlockerV1] = None

        if isinstance(entry, ConclusiveBlockerV1):
            blocker = entry
        elif isinstance(entry, dict):
            code = _normalize_code(str(entry.get("code") or entry.get("category") or "legacy_blocker"))
            raw_message = str(entry.get("message") or "").strip()
            raw_detail = entry.get("detail")
            if (not raw_message) and isinstance(entry.get("detail"), str):
                raw_message = str(entry.get("detail"))
                raw_detail = {"raw": raw_message}
            if (not raw_message) and isinstance(entry.get("raw"), str):
                raw_message = str(entry.get("raw"))
            message = raw_message or _human_message_for_code(code)
            blocker = ConclusiveBlockerV1(
                code=code,
                message=message,
                detail=scrub_sensitive_payload(raw_detail),
                phase=(str(entry.get("phase")) if entry.get("phase") else default_phase),
                recoverable=(bool(entry.get("recoverable")) if entry.get("recoverable") is not None else None),
            )
        elif isinstance(entry, str):
            code, detail = _parse_legacy_reason(entry)
            blocker = ConclusiveBlockerV1(
                code=code,
                message=_human_message_for_code(code, fallback=entry),
                detail=scrub_sensitive_payload(detail),
                phase=default_phase,
                recoverable=None,
            )

        if blocker is None:
            continue

        key = (
            blocker.code,
            blocker.message,
            blocker.phase or "",
            str(blocker.recoverable) if blocker.recoverable is not None else "",
            _safe_json_dumps(blocker.detail),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(blocker)

    return out


def is_critical_coverage_complete(
    summary: CoverageSummaryV1,
    blockers: Optional[List[ConclusiveBlockerV1]] = None,
) -> bool:
    requested = sorted(set([str(e).strip() for e in (summary.engines_requested or []) if str(e).strip()]))
    executed = sorted(set([str(e).strip() for e in (summary.engines_executed or []) if str(e).strip()]))

    return bool(
        len(requested) > 0
        and requested == executed
        and int(summary.inputs_tested or 0) > 0
        and len(summary.deps_missing or []) == 0
        and bool(summary.preflight_ok)
        and bool(summary.execution_ok)
        and bool(summary.verdict_phase_completed)
        and len(blockers or []) == 0
    )


def issue_verdict_v1(
    *,
    has_confirmed_finding: bool,
    requested_verdict: Optional[str],
    summary: CoverageSummaryV1,
    blockers: Optional[List[ConclusiveBlockerV1]],
) -> VerdictDecisionV1:
    normalized_blockers = adapt_legacy_blockers(
        [b.model_dump() if isinstance(b, ConclusiveBlockerV1) else b for b in (blockers or [])],
        default_phase="verdict",
    )

    requested = str(requested_verdict or "").upper().strip()

    # Findings always override coverage completeness.
    if has_confirmed_finding or requested == "VULNERABLE":
        return VerdictDecisionV1(
            verdict="VULNERABLE",
            conclusive=True,
            vulnerable=True,
            blockers=[],
        )

    # Frontend/backward-compatible guard: INCONCLUSIVE never elevates.
    if requested == "INCONCLUSIVE":
        if not normalized_blockers:
            normalized_blockers = [
                ConclusiveBlockerV1(
                    code="coverage_incomplete",
                    message=_human_message_for_code("coverage_incomplete"),
                    detail={"reason": "backend_marked_inconclusive"},
                    phase="verdict",
                    recoverable=True,
                )
            ]
        return VerdictDecisionV1(
            verdict="INCONCLUSIVE",
            conclusive=False,
            vulnerable=False,
            blockers=normalized_blockers,
        )

    if (requested == "NO_VULNERABLE") and is_critical_coverage_complete(summary, normalized_blockers):
        return VerdictDecisionV1(
            verdict="NO_VULNERABLE",
            conclusive=True,
            vulnerable=False,
            blockers=[],
        )

    if requested == "NO_VULNERABLE":
        normalized_blockers = normalized_blockers + [
            ConclusiveBlockerV1(
                code="coverage_incomplete",
                message=_human_message_for_code("coverage_incomplete"),
                detail={"reason": "requested_no_vulnerable_without_critical_coverage"},
                phase="verdict",
                recoverable=True,
            )
        ]
        normalized_blockers = adapt_legacy_blockers(
            [b.model_dump() for b in normalized_blockers],
            default_phase="verdict",
        )

    if not normalized_blockers:
        normalized_blockers = [
            ConclusiveBlockerV1(
                code="coverage_incomplete",
                message=_human_message_for_code("coverage_incomplete"),
                detail={"reason": "insufficient_critical_fields"},
                phase="verdict",
                recoverable=True,
            )
        ]

    return VerdictDecisionV1(
        verdict="INCONCLUSIVE",
        conclusive=False,
        vulnerable=False,
        blockers=normalized_blockers,
    )

