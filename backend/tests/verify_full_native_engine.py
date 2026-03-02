import asyncio
import os
import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

async def test_full_native_engine():
    from backend.v4_omni_surface import run_sqlmap_vector, engine_registry
    
    broadcast_log = AsyncMock()
    
    print("--- Phase 1: Native SQLMap Techniques (B, T, E, U, S, Q) ---")
    with patch('asyncio.create_subprocess_exec') as mock_exec, \
         patch('backend.core.cerberus_http_client.CerberusHTTPClient') as mock_client:
        
        # Test configurations for standard techniques
        tests = [
            {"tech": "B", "vector": "VectorBoolean", "outcome": "vulnerable"},
            {"tech": "T", "vector": "VectorTime", "outcome": "vulnerable"},
            {"tech": "E", "vector": "VectorError", "outcome": "vulnerable"},
            {"tech": "U", "vector": "VectorUnion", "outcome": "vulnerable"},
            {"tech": "S", "vector": "VectorStacked", "outcome": "vulnerable"},
            {"tech": "Q", "vector": "VectorInline", "outcome": "vulnerable"},
        ]
        
        for t in tests:
            tech_code = t["tech"]
            vector_class = t["vector"]
            print(f"Testing Native {vector_class} (Tech {tech_code})...")
            
            cmd = ["python", "sqlmap.py", "-u", "http://test.com", f"--technique={tech_code}"]
            
            # Patch the specific vector class in v4_omni_surface
            module_name = vector_class.lower().replace("vector", "")
            with patch(f'backend.core.vector_{module_name}.{vector_class}') as mock_v_cls:
                mock_v_instance = mock_v_cls.return_value
                mock_v_instance.run = AsyncMock(return_value={"status": t["outcome"], "evidence": "Integration Test Success"})
                
                await run_sqlmap_vector(f"{tech_code}_TEST", cmd, broadcast_log)
                
                assert mock_v_instance.run.called, f"Native vector {vector_class} was NOT called for tech {tech_code}"
                assert not mock_exec.called, f"Subprocess was called for tech {tech_code} but it should be NATIVE"
                print(f"OK: {vector_class} correctly routed and executed.")
                
            mock_exec.reset_mock()

    print("\n--- Phase 2: AIIE Engine Naming (Canonical 'AIIE') ---")
    # We test that the AIIE engine reports results as "AIIE"
    aiie_engine = engine_registry.get_engine("aiie")
    if aiie_engine:
        # We patch CerberusAIIE inside backend.aiie_engine
        with patch('backend.aiie_engine.CerberusAIIE') as mock_aiie_cls:
            mock_instance = mock_aiie_cls.return_value
            from backend.aiie_engine import AIIEResult
            mock_instance.detect_sqli = AsyncMock(return_value=AIIEResult(True, "AIIE", "Evidence", "Payload", 0.99))
            
            result = await aiie_engine.run("http://test.com", {}, broadcast_log)
            print(f"AIIE Result Vector: {result.vector}")
            assert result.vector == "AIIE", f"Expected vector name 'AIIE', got '{result.vector}'"
            print("OK: AIIE engine reports correctly as 'AIIE'.")

if __name__ == "__main__":
    try:
        asyncio.run(test_full_native_engine())
        print("\nAll native engine and naming tests passed successfully!")
    except Exception as e:
        print(f"\nTests failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
