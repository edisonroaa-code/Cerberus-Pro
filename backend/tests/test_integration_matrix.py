
import unittest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from backend.core.chain_orchestrator import ChainOrchestrator, VulnerabilityType, ChainLink, VulnerabilityFinding
from backend.offensiva.sandbox_runner import SandboxRunner, SandboxResult

class TestChainIntegration(unittest.IsolatedAsyncioTestCase):

    async def test_pivot_execution(self):
        # Test that _execute_link calls LateralOrchestrator when technique is 'pivot'
        orchestrator = ChainOrchestrator()
        
        # Mock finding
        finding = VulnerabilityFinding(
            type=VulnerabilityType.RCE,
            endpoint="/admin",
            parameter="cmd",
            confidence=1.0
        )
        
        # Mock link
        link = ChainLink(
            source_vuln=VulnerabilityType.RCE,
            target_vuln=VulnerabilityType.LATERAL_MOVEMENT,
            technique="pivot",
            confidence=1.0
        )
        
        # Mock LateralOrchestrator inside the method's import scope
        # Since we can't easily patch local imports, we'll patch the module in sys.modules
        with patch('backend.offensiva.lateral_movement.LateralOrchestrator') as MockLatOrch:
            mock_instance = MockLatOrch.return_value
            # Mock explore_network to return some hosts
            mock_host = MagicMock()
            mock_host.ip = "192.168.1.100"
            mock_host.open_ports = [80]
            mock_instance.explore_network = AsyncMock(return_value=[mock_host])
            
            result = await orchestrator._execute_link(link, finding)
            
            self.assertTrue(result["success"])
            self.assertIn("Lateral movement complete", result["output"])
            self.assertIn("192.168.1.100", result["evidence"])

class TestSandboxRunner(unittest.IsolatedAsyncioTestCase):
    
    @patch('asyncio.create_subprocess_exec')
    async def test_docker_command_generation(self, mock_exec):
        runner = SandboxRunner()
        
        # Mock process
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"hello", b""))
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc
        
        await runner.run("echo test", image="alpine", allow_network=False)
        
        # Verify docker command args
        args = mock_exec.call_args[0]
        self.assertEqual(args[0], "docker")
        self.assertEqual(args[1], "run")
        self.assertIn("--network", args)
        self.assertIn("none", args) # verification of default network mode or passed arg
        self.assertIn("alpine", args)

if __name__ == '__main__':
    unittest.main()
