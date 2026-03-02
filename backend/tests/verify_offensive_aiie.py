import asyncio
import os
import sys
from unittest.mock import MagicMock, AsyncMock, patch
import json

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

async def test_offensive_aiie():
    from backend.aiie_engine import CerberusAIIE
    
    broadcast = AsyncMock()
    engine = CerberusAIIE(broadcast)
    
    print("--- Testing Predatory AIIE Mode ---")
    
    # Mock Cortex AI to return a lethal payload
    with patch('backend.core.cortex_ai.generate_lethal_payload') as mock_gen, \
         patch('httpx.AsyncClient') as mock_httpx_cls:
        
        mock_gen.return_value = {
            "payload": "' OR 1=1 UNION SELECT 'CERBERUS_LETHAL' --",
            "reasoning": "Explotación por canal lateral de memoria detectada por Cortex",
            "confidence": 0.98,
            "is_lethal": True
        }
        
        # Mock HTTPX response to simulate a successful delay/hit
        mock_client = mock_httpx_cls.return_value.__aenter__.return_value
        mock_client.get = AsyncMock()
        
        # We need a custom measure_response to simulate a hit
        original_measure = engine._measure_response
        async def mock_measure(client, url, params, headers):
            # If our lethal payload is in params, return a long delay
            for v in params.values():
                if 'CERBERUS_LETHAL' in str(v):
                    return 5.0
            return 0.1
            
        engine._measure_response = mock_measure
        
        result = await engine.detect_sqli("http://predator.test", {"id": "1"}, risk_level=3)
        
        print(f"Result Vector: {result.vector}")
        print(f"Vulnerable: {result.vulnerable}")
        print(f"Payload: {result.payload}")
        print(f"Evidence: {result.evidence}")
        
        assert result.vulnerable is True
        assert result.vector == "PREDATORY_AI"
        assert "CERBERUS_LETHAL" in result.payload
        
        print("\nOK: Predatory AIIE correctly generated and deployed a lethal payload.")

if __name__ == "__main__":
    try:
        asyncio.run(test_offensive_aiie())
        print("\nOffensive AI weaponization verified successfully!")
    except Exception as e:
        print(f"\nVerification failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
