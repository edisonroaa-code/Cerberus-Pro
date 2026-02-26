"""
Conftest centralizado — Fixtures compartidos para todo el test suite.
Fase 5: Estabilidad Técnica.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from backend.core.coverage_ledger import (
    CoverageLedger,
    VectorCoverageRecord,
    EngineCoverageRecord,
    PhaseCompletionRecord,
    ConclusiveBlocker,
    CoverageStatus,
)
from backend.core.verdict_contract import VerdictStatus, VerdictDictum
from backend.core.orchestrator_fsm import Orchestrator, OrchestratorPhase


# ---------------------------------------------------------------------------
# CoverageLedger Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def base_ledger():
    """Ledger base para tests de cobertura y veredictos."""
    return CoverageLedger(
        scan_id="test_scan_001",
        target_url="http://example.com",
        budget_max_time_ms=300000,
        budget_max_retries=3,
        budget_max_parallel=5,
        budget_max_phase_time_ms=60000,
        engines_requested=["sqlmap", "burp", "zaproxy"],
    )


@pytest.fixture
def complete_ledger(base_ledger):
    """Ledger con cobertura completa (todos los motores ejecutados, inputs probados)."""
    ledger = base_ledger
    ledger.engines_executed = ["sqlmap", "burp", "zaproxy"]
    ledger.inputs_found = 10
    ledger.inputs_tested = 10
    ledger.inputs_failed = 0
    return ledger


@pytest.fixture
def empty_ledger():
    """Ledger mínimo para tests unitarios simples."""
    return CoverageLedger(
        scan_id="test_unit",
        target_url="http://localhost",
        budget_max_time_ms=1000,
        budget_max_retries=1,
        budget_max_parallel=1,
        budget_max_phase_time_ms=1000,
        engines_requested=["test_engine"],
    )


# ---------------------------------------------------------------------------
# Mock Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_policy_engine():
    """Policy engine que siempre autoriza."""
    engine = MagicMock()
    engine.check_authorization.return_value = True
    return engine


@pytest.fixture
def mock_pg_store():
    """PostgresStore mockeado para tests sin DB real."""
    store = MagicMock()
    store.persist_coverage_v1 = MagicMock()
    store.persist_scan_artifacts = MagicMock()
    return store


@pytest.fixture
def mock_reporter():
    """Reporter mockeado."""
    reporter = MagicMock()
    reporter.generate_markdown_report.return_value = "# Test Report"
    reporter.log_action = MagicMock()
    return reporter


# ---------------------------------------------------------------------------
# ScanManager Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scan_manager_instance(mock_policy_engine, mock_reporter):
    """ScanManager con dependencias mockeadas, listo para tests de integración."""
    with patch("backend.core.scan_manager.get_policy_engine") as mp, \
         patch("backend.core.scan_manager.get_reporter") as mr:
        mp.return_value = mock_policy_engine
        mr.return_value = mock_reporter

        from backend.core.scan_manager import ScanManager
        manager = ScanManager(target_url="http://test-fixture.com", scan_id="fixture_scan")
        manager._persist_metrics = AsyncMock()
        yield manager
