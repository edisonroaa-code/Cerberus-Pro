
import unittest
import asyncio
import json
import gzip
import base64
from unittest.mock import MagicMock, patch, AsyncMock
from backend.offensiva.evidence_exfil import EvidenceExfilOrchestrator, ExfilChannel, ExfilResult

class TestEvidenceExfil(unittest.IsolatedAsyncioTestCase):

    @patch('backend.offensiva.evidence_exfil.get_post_exfiltration_policy')
    async def test_exfil_channel_selection(self, mock_get_policy):
        # Mock policy to allow
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = True
        mock_get_policy.return_value = mock_policy
        orchestrator = EvidenceExfilOrchestrator()
        # Mock channels to succeed
        orchestrator._try_http = AsyncMock(return_value=True)
        
        data = b"secret_data"
        result = await orchestrator.exfiltrate(data, "target.com", "passwords.txt", ExfilChannel.AUTO)
        
        self.assertTrue(result.success)
        self.assertEqual(result.channel, ExfilChannel.HTTP)
        self.assertEqual(result.bytes_sent, len(data))

    async def test_payload_preparation(self):
        orchestrator = EvidenceExfilOrchestrator()
        data = b"hello world"
        payload = orchestrator._prepare_payload(data, "test.txt")
        
        # Reverse process to verify
        decompressed = gzip.decompress(payload)
        meta = json.loads(decompressed)
        
        self.assertEqual(meta["filename"], "test.txt")
        self.assertEqual(base64.b64decode(meta["content"]), data)

    @patch('backend.offensiva.evidence_exfil.get_post_exfiltration_policy')
    async def test_policy_blocking(self, mock_get_policy):
        # Mock policy to block
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = False
        mock_get_policy.return_value = mock_policy
        
        orchestrator = EvidenceExfilOrchestrator()
        result = await orchestrator.exfiltrate(b"sensitive", "protected_target.com", "file.txt")
        
        self.assertFalse(result.success)
        self.assertIn("Blocked by policy", result.message)

if __name__ == '__main__':
    unittest.main()
