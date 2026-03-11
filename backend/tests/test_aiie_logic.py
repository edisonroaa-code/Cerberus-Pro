import asyncio
import time
from typing import Dict, Any, Callable
from dataclasses import dataclass

# Mock AIIEResult and CerberusAIIE to test the logic
@dataclass
class AIIEResult:
    vulnerable: bool
    vector: str
    evidence: str
    payload: str
    confidence: float
    loot: Dict[str, str] = None

class MockCerberusAIIE:
    def __init__(self):
        self.ua_pool = ["MockUA"]
        
    def _mutate_ast_logical(self, condition: bool) -> str:
        return "1=1" if condition else "1=2"

    async def test_logic(self, delay_true: float, delay_false: float, avg_base: float, std_base: float):
        # This simulates the logic I just added to aiie_engine.py
        z_score = (delay_true - avg_base) / (std_base or 0.001)
        
        print(f"DEBUG: Z-Score={z_score:.2f}, DelayTrue={delay_true:.2f}s")
        
        # Stricter threshold for fallback/low confidence
        hit_threshold = 12.0 
        
        if z_score > hit_threshold or (delay_true > avg_base + 3.0):
            print("INFO: Posible brecha detectada. Iniciando verificación diferencial...")
            
            # Verification: Test with FALSE
            print(f"DEBUG: Testing FALSE payload... DelayFalse={delay_false:.2f}s")
            
            if delay_false > (avg_base + 1.5):
                print(f"WARNING: Verificación fallida (Ruido detectado). Latencia en FALSE: {delay_false:.2f}s")
                return False # Not vulnerable
            
            print("SUCCESS: Objetivo VULNERABLE confirmado vía análisis diferencial")
            return True
        
        print("INFO: No se detectó vulnerabilidad significativa.")
        return False

async def main():
    engine = MockCerberusAIIE()
    avg_base = 0.5
    std_base = 0.1
    
    print("\n--- CASE 1: True vulnerability (TRUE slow, FALSE fast) ---")
    # Z-score = (5.0 - 0.5) / 0.1 = 45 (High)
    res1 = await engine.test_logic(delay_true=5.0, delay_false=0.5, avg_base=avg_base, std_base=std_base)
    assert res1 is True, "Should be vulnerable"

    print("\n--- CASE 2: Network Noise (Both slow) ---")
    res2 = await engine.test_logic(delay_true=5.0, delay_false=4.8, avg_base=avg_base, std_base=std_base)
    assert res2 is False, "Should NOT be vulnerable (noise)"

    print("\n--- CASE 3: Below threshold ---")
    # Z-score = (1.0 - 0.5) / 0.1 = 5
    res3 = await engine.test_logic(delay_true=1.0, delay_false=0.5, avg_base=avg_base, std_base=std_base)
    assert res3 is False, "Should be below threshold"

    print("\n--- ALL LOGIC TESTS PASSED ---")

if __name__ == "__main__":
    asyncio.run(main())
