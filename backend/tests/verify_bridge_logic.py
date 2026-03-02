import asyncio
import os
import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

async def test_bridge_logic():
    from backend.v4_omni_surface import run_sqlmap_vector
    
    # Mock broadcast_log
    broadcast_log = AsyncMock()
    
    # Mock subprocess calls
    with patch('asyncio.create_subprocess_exec') as mock_exec, \
         patch('backend.core.cerberus_http_client.CerberusHTTPClient') as mock_client:
        
        mock_proc = AsyncMock()
        mock_proc.stdout.readline.return_value = b''
        mock_proc.wait = AsyncMock(return_value=0)
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc
        
        # 1. Test UNION (U) - Should use Subprocess (Fallback)
        print("Testing UNION (U)...")
        cmd_u = ["python", "sqlmap.py", "-u", "http://test.com", "--technique=U"]
        await run_sqlmap_vector("UNION_TEST", cmd_u, broadcast_log)
        
        # Check if subprocess was called
        called_cmds = [call.args for call in mock_exec.call_args_list]
        assert any("U" in str(arg) for arg in called_cmds[0]), "UNION should have triggered subprocess"
        print("OK: UNION correctly used subprocess fallback.")
        
        mock_exec.reset_mock()
        
        # 2. Test BOOLEAN (B) - Should use Native Bridge
        print("Testing BOOLEAN (B)...")
        cmd_b = ["python", "sqlmap.py", "-u", "http://test.com", "--technique=B"]
        # Mock VectorBoolean run
        with patch('backend.core.vector_boolean.VectorBoolean') as mock_vb:
            mock_vb_instance = mock_vb.return_value
            mock_vb_instance.run = AsyncMock(return_value={"status": "not_vulnerable"})
            
            await run_sqlmap_vector("BOOLEAN_TEST", cmd_b, broadcast_log)
            
            # Check if native vector was called
            assert mock_vb_instance.run.called, "BOOLEAN should have triggered native engine"
            assert not mock_exec.called, "BOOLEAN should NOT have triggered subprocess"
            print("OK: BOOLEAN correctly used native engine.")

        # 3. Test Skip Bridge Env Var
        print("Testing Skip Bridge Env Var...")
        os.environ["CERBERUS_SKIP_NATIVE_BRIDGE"] = "true"
        mock_exec.reset_mock()
        
        await run_sqlmap_vector("SKIP_TEST", cmd_b, broadcast_log)
        assert mock_exec.called, "Skip bridge env var should force subprocess"
        print("OK: Skip bridge env var correctly forced subprocess.")
        
        del os.environ["CERBERUS_SKIP_NATIVE_BRIDGE"]

if __name__ == "__main__":
    asyncio.run(test_bridge_logic())
    print("\nAll routing tests passed!")
