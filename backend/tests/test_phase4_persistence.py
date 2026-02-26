import pytest
import asyncio
from unittest.mock import MagicMock, patch
from backend.core.scan_manager import ScanManager
from backend.core.orchestrator_fsm import OrchestratorPhase
from backend.core.coverage_ledger import CoverageStatus

@pytest.mark.asyncio
async def test_scan_manager_persistence_call():
    """Verifica que ScanManager llame a _persist_metrics al finalizar el escaneo."""
    target_url = "http://test-persistence.com"
    scan_id = "test_scan_persistence"
    
    # Mock de dependencias externas
    with patch("backend.core.scan_manager.get_policy_engine") as mock_policy, \
         patch("backend.core.scan_manager.get_reporter") as mock_reporter, \
         patch("backend.core.scan_manager.Orchestrator") as mock_orch_cls:
        
        mock_policy.return_value.check_authorization.return_value = True
        
        # Configurar el mock del orchestrador
        mock_orch = mock_orch_cls.return_value
        mock_orch.context.scan_id = scan_id
        mock_orch.context.execution_results = {"findings": []}
        mock_orch.context.escalation_attempts = {}
        mock_orch.get_phase_sequence.return_value = [OrchestratorPhase.PREFLIGHT, OrchestratorPhase.VERDICT]
        
        # Mock de execute_phase para evitar ejecución real
        async def mock_execute(phase, handler, ctx):
            return True
        mock_orch.execute_phase = mock_execute
        
        manager = ScanManager(target_url=target_url, scan_id=scan_id)
        
        # Mock de _persist_metrics para verificar la llamada
        manager._persist_metrics = MagicMock(side_effect=asyncio.sleep(0))
        
        await manager.run_scan()
        
        # Verificar que se llamó a persistencia
        manager._persist_metrics.assert_called_once()
        ledger = manager._persist_metrics.call_args[0][0]
        assert ledger.scan_id == scan_id
        assert ledger.target_url == target_url

@pytest.mark.asyncio
async def test_persist_metrics_logic():
    """Verifica la lógica interna de _persist_metrics y la integración con PG_STORE."""
    target_url = "http://test-logic.com"
    scan_id = "test_scan_logic"
    
    from backend.core.coverage_ledger import CoverageLedger
    ledger = CoverageLedger(
        scan_id=scan_id,
        target_url=target_url,
        budget_max_time_ms=1000,
        budget_max_retries=1,
        budget_max_parallel=1,
        budget_max_phase_time_ms=1000,
        engines_requested=["test_engine"]
    )
    ledger.status = "completed"
    
    manager = ScanManager(target_url=target_url, scan_id=scan_id)
    manager.orchestrator.context.execution_results = {"findings": []}
    
    # Mock de PG_STORE
    mock_pg = MagicMock()
    with patch("backend.ares_api.PG_STORE", mock_pg):
        await manager._persist_metrics(ledger)
        
        mock_pg.persist_coverage_v1.assert_called_once()
        args = mock_pg.persist_coverage_v1.call_args.kwargs
        
        assert args["scan_id"] == scan_id
        assert args["verdict"] == "INCONCLUSIVE" # Ledger is empty, so it should be inconclusive
        assert args["conclusive"] is False
        assert args["job_status"] == "completed"

@pytest.mark.asyncio
async def test_scan_manager_full_ledger_population():
    """Verifica que el ledger se pueble correctamente durante las fases."""
    target_url = "http://test-full.com"
    scan_id = "test_scan_full"
    
    from unittest.mock import AsyncMock
    
    with patch("backend.core.scan_manager.get_policy_engine") as mock_policy, \
         patch("backend.core.scan_manager.get_reporter") as mock_reporter:
        
        mock_policy.return_value.check_authorization.return_value = True
        
        manager = ScanManager(target_url=target_url, scan_id=scan_id)
        
        # Mock de persistencia para evitar DB real (async)
        manager._persist_metrics = AsyncMock()
        
        # Mock de EngineOrchestrator para evitar escaneo real
        with patch("backend.core.scan_manager.EngineOrchestrator") as mock_engine_orch:
            # scan_all must return an awaitable
            mock_engine_orch.return_value.scan_all = AsyncMock(return_value=[])
            
            await manager.run_scan()
            
            # Verificar Ledger
            ledger = manager.ledger
            assert ledger.inputs_found > 0, f"inputs_found should be > 0, got {ledger.inputs_found}"
            assert len(ledger.phase_records) >= 3, f"Expected >= 3 phase records, got {len(ledger.phase_records)}: {[p.phase for p in ledger.phase_records]}"
            
            phases = [p.phase for p in ledger.phase_records]
            assert "preflight" in phases
            assert "discovery" in phases
            assert "execution" in phases
            
            print(f"✓ Ledger populated with {len(ledger.phase_records)} phases: {phases}")

if __name__ == "__main__":
    asyncio.run(test_scan_manager_persistence_call())
    asyncio.run(test_persist_metrics_logic())
    asyncio.run(test_scan_manager_full_ledger_population())
