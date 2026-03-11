import asyncio
import sys
import os
import logging
from dotenv import load_dotenv

# Configuration de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("health_test")

# Add root to sys.path
sys.path.append(os.getcwd())
load_dotenv()

from backend.core.cortex_ai import check_ai_health
from backend.core.scan_manager import ScanManager

async def test_ai_health():
    print("--- STEP 1: Testing check_ai_health (Real API) ---")
    health = await check_ai_health()
    print(f"AI Health Response: {health}")
    
    if not health:
        print("ABORTING STEP 2: Real API is not working, cannot test 'Success' case.")
        return

    print("\n--- STEP 2: Testing ScanManager with AI Guard (Success Case) ---")
    manager = ScanManager("http://testphp.vulnweb.com", scan_id="health_test_ok")
    try:
        await manager._handle_preflight(manager.orchestrator.context)
        print("Preflight SUCCESS: AI Guard allowed the scan.")
    except RuntimeError as e:
        print(f"Preflight FAILED (Unexpected): {e}")

    print("\n--- STEP 3: Testing ScanManager with AI Guard (Failure Case) ---")
    # Simulate missing API key
    os.environ["GEMINI_API_KEY_BACKUP"] = os.environ.get("GEMINI_API_KEY", "")
    os.environ["GEMINI_API_KEY"] = ""
    
    # Force reload of client in cortex_ai (it's lazy initialized)
    import backend.core.cortex_ai
    backend.core.cortex_ai._client = None 

    manager_fail = ScanManager("http://testphp.vulnweb.com", scan_id="health_test_fail")
    try:
        await manager_fail._handle_preflight(manager_fail.orchestrator.context)
        print("Preflight SUCCESS (Unexpected): AI Guard failed to block.")
    except RuntimeError as e:
        print(f"Preflight BLOCKED as expected: {e}")
    
    # Restore API key
    os.environ["GEMINI_API_KEY"] = os.environ.get("GEMINI_API_KEY_BACKUP", "")
    backend.core.cortex_ai._client = None

if __name__ == "__main__":
    asyncio.run(test_ai_health())
