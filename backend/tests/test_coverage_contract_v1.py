from backend.core.coverage_contract_v1 import (
    ConclusiveBlockerV1,
    CoverageSummaryV1,
    adapt_legacy_blockers,
    issue_verdict_v1,
)


def _complete_summary() -> CoverageSummaryV1:
    return CoverageSummaryV1(
        coverage_percentage=100.0,
        engines_requested=["SQLMAP"],
        engines_executed=["SQLMAP"],
        inputs_found=2,
        inputs_tested=2,
        inputs_failed=0,
        deps_missing=[],
        preflight_ok=True,
        execution_ok=True,
        verdict_phase_completed=True,
        status="completed",
        total_duration_ms=1200,
    )


def test_legacy_blockers_are_normalized_to_contract():
    blockers = adapt_legacy_blockers(
        [
            "missing_dependencies:playwright",
            {"code": "no_forms_found", "message": "No forms found"},
            {"category": "engine_errors", "detail": "timeout"},
        ],
        default_phase="verdict",
    )
    assert len(blockers) == 3
    assert all(isinstance(b, ConclusiveBlockerV1) for b in blockers)
    assert all(isinstance(b.code, str) and b.code for b in blockers)
    assert all(isinstance(b.message, str) and b.message for b in blockers)


def test_no_vulnerable_requires_complete_critical_coverage():
    summary = _complete_summary()
    summary.inputs_tested = 0  # break critical coverage
    verdict = issue_verdict_v1(
        has_confirmed_finding=False,
        requested_verdict="NO_VULNERABLE",
        summary=summary,
        blockers=[],
    )
    assert verdict.verdict == "INCONCLUSIVE"
    assert verdict.conclusive is False
    assert verdict.vulnerable is False
    assert any(b.code == "coverage_incomplete" for b in verdict.blockers)


def test_complete_no_findings_allows_no_vulnerable():
    verdict = issue_verdict_v1(
        has_confirmed_finding=False,
        requested_verdict="NO_VULNERABLE",
        summary=_complete_summary(),
        blockers=[],
    )
    assert verdict.verdict == "NO_VULNERABLE"
    assert verdict.conclusive is True
    assert verdict.vulnerable is False
    assert verdict.blockers == []


def test_confirmed_finding_overrides_coverage_gaps():
    summary = _complete_summary()
    summary.execution_ok = False
    verdict = issue_verdict_v1(
        has_confirmed_finding=True,
        requested_verdict="INCONCLUSIVE",
        summary=summary,
        blockers=[ConclusiveBlockerV1(code="engine_errors", message="engine failed")],
    )
    assert verdict.verdict == "VULNERABLE"
    assert verdict.conclusive is True
    assert verdict.vulnerable is True


def test_backend_inconclusive_is_never_elevated():
    verdict = issue_verdict_v1(
        has_confirmed_finding=False,
        requested_verdict="INCONCLUSIVE",
        summary=_complete_summary(),
        blockers=[],
    )
    assert verdict.verdict == "INCONCLUSIVE"
    assert verdict.conclusive is False
