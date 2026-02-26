
import unittest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from backend.core.scan_manager import ScanManager
from backend.core.orchestrator_fsm import OrchestratorPhase

class TestSystemSync(unittest.IsolatedAsyncioTestCase):

    @patch('backend.core.scan_manager.waf_fingerprint', new_callable=AsyncMock)
    @patch('backend.core.scan_manager.EngineOrchestrator')
    @patch('backend.core.scan_manager.ChainOrchestrator')
    @patch('backend.core.scan_manager.get_reporter')
    @patch('backend.core.scan_manager.get_policy_engine')
    async def test_end_to_end_flow(
        self,
        mock_get_policy,
        mock_get_reporter,
        MockChainOrch,
        MockEngineOrch,
        mock_waf_fingerprint,
    ):
        # Setup mocks
        mock_policy = MagicMock()
        mock_policy.check_authorization.return_value = True
        mock_get_policy.return_value = mock_policy
        
        mock_reporter = MagicMock()
        mock_get_reporter.return_value = mock_reporter

        mock_waf_fingerprint.return_value = {"vendor": "mock-waf", "detected": False}

        mock_engine_orch = MockEngineOrch.return_value
        mock_finding = MagicMock()
        mock_finding.engine = "sqlmap"
        mock_finding.type = "rce"
        mock_finding.endpoint = "/admin"
        mock_finding.parameter = "cmd"
        mock_finding.evidence = "mock-evidence"
        mock_finding.severity = "high"
        mock_finding.confidence = 0.9
        mock_engine_orch.scan_all = AsyncMock(return_value=[mock_finding])
        
        mock_chain_instance = MockChainOrch.return_value
        mock_chain_instance.discover_chains.return_value = [MagicMock(objective="rce")]
        mock_chain_instance.execute_chain = AsyncMock(return_value=(True, "Success"))
        
        # Initialize Manager
        manager = ScanManager("http://test-target.local", "test-scan-id")
        
        # Run Scan
        await manager.run_scan()
        
        # Debug Report
        import json
        report = manager.orchestrator.get_phase_status_report()
        print("\n=== SYSTEM SYNC DEBUG REPORT ===")
        print(json.dumps(report, indent=2, default=str))
        print("================================")
        
        # Verify Flow
        # 1. Policy check called
        mock_policy.check_authorization.assert_called()
        
        # 2. Reporter initialized
        mock_get_reporter.assert_called()

        # 2.5 Discovery + execution are mocked
        mock_waf_fingerprint.assert_awaited()
        mock_engine_orch.scan_all.assert_awaited()
        
        # 3. Chain Orchestrator called (Escalation Phase)
        mock_chain_instance.discover_chains.assert_called()
        mock_chain_instance.execute_chain.assert_called()
        
        # 4. Reporter called (log_action during escalation, generate_markdown_report during verdict)
        mock_reporter.log_action.assert_called()
        mock_reporter.generate_markdown_report.assert_called()

if __name__ == '__main__':
    unittest.main()
