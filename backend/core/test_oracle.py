import asyncio
import logging
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend.core.cortex_ai import analyze_injection_response

logging.basicConfig(level=logging.DEBUG)

html_baseline = """
<html><body>
  <h1>User Profile</h1>
  <p>Status: Active</p>
  <div id="csrf">TOKEN_A39V10</div>
  <div id="timestamp">12:00:01</div>
</body></html>
"""

html_true_injection = """
<html><body>
  <h1>User Profile</h1>
  <p>Status: Active</p>
  <div id="csrf">TOKEN_B99X11</div>
  <div id="timestamp">12:00:03</div>
</body></html>
"""

html_false_injection = """
<html><body>
  <h1>User Profile</h1>
  <p>Status: Active</p>
  <div id="csrf">TOKEN_C11Z00</div>
  <div id="timestamp">12:00:05</div>
</body></html>
"""

html_false_injection_vulnerable = """
<html><body>
  <h1>User Profile</h1>
  <!-- SQL Syntax Error: Unclosed quotation mark -->
  <div id="csrf">TOKEN_C11Z00</div>
  <div id="timestamp">12:00:05</div>
</body></html>
"""

async def test_oracle():
    print("--- Test 1: Mero Ruido Dinámico (No Vulnerable) ---")
    result_noise = await analyze_injection_response(
        baseline_content=html_baseline,
        true_content=html_true_injection,
        false_content=html_false_injection,
        vector_type="Boolean-based blind"
    )
    print(f"Resultado Ruido: {result_noise}")
    print("\n--- Test 2: Inyección SQL Oculta (Vulnerable) ---")
    result_vuln = await analyze_injection_response(
        baseline_content=html_baseline,
        true_content=html_true_injection,
        false_content=html_false_injection_vulnerable,
        vector_type="Boolean-based blind"
    )
    print(f"Resultado Vulnerable: {result_vuln}")

if __name__ == "__main__":
    asyncio.run(test_oracle())
