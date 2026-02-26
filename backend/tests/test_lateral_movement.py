
import unittest
import asyncio
from unittest.mock import patch, MagicMock
from backend.offensiva.lateral_movement import NetworkScanner, ScanMethod, HostInfo, LateralOrchestrator

class TestLateralMovement(unittest.IsolatedAsyncioTestCase):

    @patch('shutil.which')
    def test_scanner_dependency_check(self, mock_which):
        # Simulator nmap missing
        mock_which.return_value = None
        scanner = NetworkScanner(method=ScanMethod.NMAP)
        # Should fall back to CONNECT
        self.assertEqual(scanner.method, ScanMethod.CONNECT)

    @patch('asyncio.create_subprocess_shell')
    async def test_nmap_scan_parsing(self, mock_subprocess):
        # Mock nmap output
        nmap_output = """
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-16 12:00 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000045s latency).
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for database (192.168.1.50)
Host is up (0.00030s latency).
PORT     STATE SERVICE
5432/tcp open  postgresql

Nmap done: 2 IP addresses (2 hosts up) scanned in 0.12 seconds
"""
        mock_proc = MagicMock()
        # Fix: communicate is awaited, so it must return a Future
        future = asyncio.Future()
        future.set_result((nmap_output.encode(), b""))
        mock_proc.communicate.return_value = future
        
        mock_proc.returncode = 0
        mock_subprocess.return_value = mock_proc

        scanner = NetworkScanner(method=ScanMethod.NMAP)
        # Force method back to NMAP even if local doesn't have it, for testing logic
        scanner.method = ScanMethod.NMAP 
        
        hosts = await scanner.scan_subnet("192.168.1.0/24")
        
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].ip, "127.0.0.1")
        self.assertEqual(hosts[0].open_ports, [22, 80])
        self.assertEqual(hosts[1].ip, "192.168.1.50")
        self.assertEqual(hosts[1].services[5432], "postgresql")

    async def test_orchestrator_flow(self):
        # Integration-like test with mocked scanner
        with patch.object(NetworkScanner, 'scan_subnet') as mock_scan:
            mock_scan.return_value = [
                HostInfo(ip="10.0.0.1", open_ports=[80], services={80: "http"})
            ]
            
            orch = LateralOrchestrator()
            results = await orch.explore_network("10.0.0.0/24")
            
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].ip, "10.0.0.1")

if __name__ == '__main__':
    unittest.main()
