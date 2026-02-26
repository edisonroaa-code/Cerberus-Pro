import pytest

from backend.core.chain_orchestrator import ChainOrchestrator
from backend.core.coverage_ledger import CoverageLedger
from backend.core.resource_escalation import ResourceEscalationEngine


def _ledger() -> CoverageLedger:
    return CoverageLedger(
        scan_id="preflight_test_scan",
        target_url="http://example.com",
        budget_max_time_ms=60000,
        budget_max_retries=2,
        budget_max_parallel=2,
        budget_max_phase_time_ms=30000,
        engines_requested=["sqlmap"],
    )


@pytest.mark.asyncio
async def test_resource_preflight_registers_missing_dependency_blocker():
    ledger = _ledger()
    engine = ResourceEscalationEngine()

    summary = await engine.run_preflight_checks(
        coverage_ledger=ledger,
        required_dependencies=["definitely_missing_dependency_xyz"],
        phase_name="preflight",
    )

    assert summary["ok"] is False
    assert "definitely_missing_dependency_xyz" in summary["missing"]
    assert "definitely_missing_dependency_xyz" in ledger.deps_missing
    assert any(b.category == "missing_deps" for b in ledger.conclusive_blockers)
    assert any(p.phase == "preflight" for p in ledger.phase_records)


@pytest.mark.asyncio
async def test_chain_orchestrator_preflight_blocks_execution_when_missing_dependency():
    orchestrator = ChainOrchestrator()
    ledger = _ledger()

    summary = await orchestrator.run_preflight(
        chain=None,
        coverage_ledger=ledger,
        required_dependencies=["dependency_that_does_not_exist_abc"],
    )

    assert summary["ok"] is False
    assert "dependency_that_does_not_exist_abc" in summary["missing"]
    assert any(b.category == "missing_deps" for b in ledger.conclusive_blockers)
