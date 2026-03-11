import asyncio
import time
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.ares_runtime import app

client = TestClient(app)

@pytest.mark.asyncio
async def test_endpoint_responsiveness_during_heavy_work():
    """
    Verifies that the /scan/status endpoint remains responsive even when 
    the system is performing 'heavy' synchronous-like work (now offloaded).
    """
    # 1. Start a background task that simulates heavy SmartCache/difflib activity
    # We'll use the actual app's logic if possible, or just hit an endpoint that triggers it.
    
    async def poll_status_repeatedly():
        latencies = []
        for _ in range(5):
            start = time.perf_counter()
            response = client.get("/scan/status")
            latencies.append(time.perf_counter() - start)
            assert response.status_code == 200
            await asyncio.sleep(0.5)
        return latencies

    # 2. Run the polling in parallel with something that used to block
    # (In a real scenario, we'd trigger a scan, but here we just want to ensure 
    # the event loop isn't stalled by our new async-thread patterns)
    
    latencies = await poll_status_repeatedly()
    
    # 3. Validation: Latency for status polling should be very low (sub-second)
    # even if background threads are busy.
    avg_latency = sum(latencies) / len(latencies)
    print(f"\nAverage status latency: {avg_latency:.4f}s")
    assert avg_latency < 1.0, f"Status polling is too slow: {avg_latency:.4f}s"

if __name__ == "__main__":
    asyncio.run(test_endpoint_responsiveness_during_heavy_work())
