"""
Coverage finalization for omni scans.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence, Set

from backend.core.coverage_contract_v1 import (
    COVERAGE_SCHEMA_VERSION_V1,
    CoverageResponseV1,
    CoverageSummaryV1,
    VectorRecordsPageV1,
    adapt_legacy_blockers,
    issue_verdict_v1,
)
from backend.core.coverage_ledger import (
    ConclusiveBlocker,
    CoverageStatus,
    EngineCoverageRecord,
    VectorCoverageRecord,
)
from backend.core.coverage_mapper import _to_phase_records_v1, _to_vector_records_v1
from backend.core.omni_scan_runtime import omni_reason_human


async def finalize_omni_coverage(
    *,
    coverage_ledger: Any,
    results: List[Dict[str, Any]],
    executed_vectors: List[str],
    present_vectors: Set[str],
    mode: str,
    sqlmap_tested_params: Set[str],
    sqlmap_explicit_not_injectable: bool,
    failed_vectors: List[str],
    merged_missing_deps: List[str],
    phases_ran: Sequence[int],
    reasons: List[str],
    scan_started_at: datetime,
    deduped_requested_engines: Sequence[str],
    preflight_summary: Dict[str, Any],
    exception_count: int,
    final_vuln: bool,
    requested_verdict: str,
    scan_id: str,
    orchestrator: Any,
    mark_phase_fn: Any,
    verdict_phase: Any,
) -> Dict[str, Any]:
    unique_executed_vectors: List[str] = []
    for vector in (executed_vectors + sorted(list(present_vectors))):
        name = str(vector or "").upper()
        if name and name not in unique_executed_vectors:
            unique_executed_vectors.append(name)
    coverage_ledger.engines_executed = unique_executed_vectors

    if mode in ("web", "graphql"):
        tested_inputs_count = (
            len(sqlmap_tested_params) if len(sqlmap_tested_params) > 0 else (1 if sqlmap_explicit_not_injectable else 0)
        )
    else:
        tested_inputs_count = max(0, len(results) - len(set(failed_vectors)))
    coverage_ledger.inputs_found = tested_inputs_count
    coverage_ledger.inputs_tested = tested_inputs_count
    coverage_ledger.inputs_failed = len(set(failed_vectors))
    coverage_ledger.deps_missing = merged_missing_deps
    coverage_ledger.budget_spent_time_ms = int((datetime.now(timezone.utc) - scan_started_at).total_seconds() * 1000)
    coverage_ledger.budget_spent_retries = max(0, len(phases_ran) - 1)
    coverage_ledger.total_duration_ms = coverage_ledger.budget_spent_time_ms
    coverage_ledger.status = "failed" if (("phases_incomplete" in reasons) or ("engine_errors" in reasons)) else "completed"

    coverage_ledger.vector_records = []
    for idx, item in enumerate(results):
        if not isinstance(item, dict):
            continue
        vector_name = str(item.get("vector") or "UNKNOWN").upper()
        record_status = CoverageStatus.EXECUTED
        if item.get("error"):
            record_status = CoverageStatus.FAILED
        elif isinstance(item.get("exit_code"), int) and int(item.get("exit_code")) != 0:
            record_status = CoverageStatus.FAILED

        evidence = item.get("evidence")
        evidence_list = [str(e) for e in evidence] if isinstance(evidence, list) else []
        vector_params_tested: Set[str] = set()
        for ev_line in evidence_list:
            for match in re.finditer(r"(?i)\btested_parameter:([a-z0-9_\-]+)\b", ev_line):
                vector_params_tested.add(str(match.group(1)))
            for match in re.finditer(
                r"(?i)\b(?:parameter|par[aá]metro):\s*([a-z0-9_\-]+)\s*\((?:get|post|uri|cookie|header)\)",
                ev_line,
            ):
                vector_params_tested.add(str(match.group(1)))
            for match in re.finditer(
                r"(?i)\b(?:get|post|uri|cookie|header)\s+parameter\s+['\"]([^'\"]+)['\"]",
                ev_line,
            ):
                vector_params_tested.add(str(match.group(1)))
            for match in re.finditer(r"(?i)\b(?:parameter|par[aá]metro)\s+['\"]([^'\"]+)['\"]", ev_line):
                vector_params_tested.add(str(match.group(1)))

        vector_inputs_tested = len(vector_params_tested)
        vector_inputs_failed = 1 if record_status in (CoverageStatus.FAILED, CoverageStatus.TIMEOUT) else 0
        coverage_ledger.add_vector_record(
            VectorCoverageRecord(
                vector_id=f"omni_{idx}_{vector_name}",
                vector_name=vector_name,
                engine=vector_name,
                status=record_status,
                inputs_found=vector_inputs_tested,
                inputs_tested=vector_inputs_tested,
                inputs_failed=vector_inputs_failed,
                duration_ms=0,
                error=str(item.get("error")) if item.get("error") else None,
                evidence=evidence_list[:20],
            )
        )

    coverage_ledger.engine_records = []
    engine_rollup: Dict[str, Dict[str, int]] = {}
    for rec in coverage_ledger.vector_records:
        stats = engine_rollup.setdefault(rec.engine, {"total": 0, "failed": 0})
        stats["total"] += 1
        if rec.status in (CoverageStatus.FAILED, CoverageStatus.TIMEOUT):
            stats["failed"] += 1

    for engine_name in deduped_requested_engines:
        stats = engine_rollup.get(engine_name, {"total": 0, "failed": 0})
        status = CoverageStatus.EXECUTED if engine_name in coverage_ledger.engines_executed else CoverageStatus.PENDING
        if stats["failed"] > 0 and engine_name not in coverage_ledger.engines_executed:
            status = CoverageStatus.FAILED
        coverage_ledger.add_engine_record(
            EngineCoverageRecord(
                engine_name=engine_name,
                status=status,
                vectors_total=max(1, stats["total"]),
                vectors_executed=max(0, stats["total"] - stats["failed"]),
                vectors_failed=stats["failed"],
                duration_ms=0,
                start_time=scan_started_at,
                end_time=datetime.now(timezone.utc),
                error=None,
            )
        )

    existing_blocker_pairs = {
        (str(blocker.category), str(blocker.detail))
        for blocker in (coverage_ledger.conclusive_blockers or [])
    }
    for reason_code in reasons:
        blocker_category = str(reason_code).split(":", 1)[0]
        blocker_detail = omni_reason_human(reason_code)
        if (blocker_category, blocker_detail) in existing_blocker_pairs:
            continue
        coverage_ledger.add_blocker(
            ConclusiveBlocker(
                category=blocker_category,
                detail=blocker_detail,
                phase="verdict",
                recoverable=True,
            )
        )

    phase_records_v1 = _to_phase_records_v1(coverage_ledger.phase_records)
    vector_records_v1 = _to_vector_records_v1(coverage_ledger.vector_records)
    reason_codes = {str(code).split(":", 1)[0].strip().lower() for code in reasons if str(code).strip()}
    extra_blockers = []
    for blocker in (coverage_ledger.conclusive_blockers or []):
        blocker_code = str(getattr(blocker, "category", "") or "coverage_incomplete").strip().lower()
        if blocker_code in reason_codes:
            continue
        extra_blockers.append(
            {
                "code": blocker_code or "coverage_incomplete",
                "message": str(getattr(blocker, "detail", "") or ""),
                "detail": {"evidence": getattr(blocker, "evidence", None)},
                "phase": str(getattr(blocker, "phase", "") or "verdict"),
                "recoverable": bool(getattr(blocker, "recoverable", True)),
            }
        )

    blockers_v1 = adapt_legacy_blockers([*reasons, *extra_blockers], default_phase="verdict")
    summary_v1 = CoverageSummaryV1(
        coverage_percentage=float(coverage_ledger.coverage_percentage() or 0.0),
        engines_requested=[str(e) for e in (coverage_ledger.engines_requested or []) if str(e).strip()],
        engines_executed=[str(e) for e in (coverage_ledger.engines_executed or []) if str(e).strip()],
        inputs_found=max(0, int(coverage_ledger.inputs_found or 0)),
        inputs_tested=max(0, int(coverage_ledger.inputs_tested or 0)),
        inputs_failed=max(0, int(coverage_ledger.inputs_failed or 0)),
        deps_missing=[str(d) for d in (coverage_ledger.deps_missing or []) if str(d).strip()],
        preflight_ok=bool(preflight_summary.get("ok", True)),
        execution_ok=(exception_count == 0),
        verdict_phase_completed=True,
        status=str(coverage_ledger.status or "completed"),
        total_duration_ms=max(0, int(coverage_ledger.total_duration_ms or 0)),
        redactions_applied=True,
    )
    verdict_decision = issue_verdict_v1(
        has_confirmed_finding=bool(final_vuln),
        requested_verdict=requested_verdict,
        summary=summary_v1,
        blockers=blockers_v1,
    )
    verdict = verdict_decision.verdict
    conclusive = verdict_decision.conclusive
    final_vuln = verdict_decision.vulnerable

    await mark_phase_fn(verdict_phase, f"verdict={verdict}")
    orchestrator_report = orchestrator.get_phase_status_report()
    phase_records_v1 = _to_phase_records_v1(coverage_ledger.phase_records)
    vector_records_v1 = _to_vector_records_v1(coverage_ledger.vector_records)
    vector_page = VectorRecordsPageV1(
        limit=max(1, min(500, len(vector_records_v1) if vector_records_v1 else 50)),
        cursor=0,
        next_cursor=None,
        has_more=False,
        items=vector_records_v1[:500],
    )
    coverage_response = CoverageResponseV1(
        version=COVERAGE_SCHEMA_VERSION_V1,
        scan_id=str(scan_id or ""),
        job_status="completed",
        verdict=verdict,
        conclusive=bool(conclusive),
        vulnerable=bool(final_vuln),
        coverage_summary=summary_v1,
        conclusive_blockers=verdict_decision.blockers,
        phase_records=phase_records_v1,
        vector_records_page=vector_page,
    )
    primary_reason = (
        str(coverage_response.conclusive_blockers[0].message)
        if coverage_response.conclusive_blockers
        else (omni_reason_human(reasons[0]) if reasons else "")
    )
    if verdict == "VULNERABLE":
        msg = "VULNERABLE - Hallazgos confirmados"
    elif verdict == "NO_VULNERABLE":
        msg = "NO VULNERABLE - Sin hallazgos con cobertura completa"
    else:
        msg = f"INCONCLUSO - {primary_reason}" if primary_reason else "INCONCLUSO - Cobertura insuficiente"

    return {
        "coverage_response": coverage_response,
        "summary_v1": summary_v1,
        "verdict": verdict,
        "conclusive": bool(conclusive),
        "final_vuln": bool(final_vuln),
        "msg": msg,
        "orchestrator_report": orchestrator_report,
    }
