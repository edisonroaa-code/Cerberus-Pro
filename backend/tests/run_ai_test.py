import asyncio
import logging
import os
from backend.engines.base import EngineConfig
from backend.engines.advanced_payload_adapter import AdvancedPayloadAdapter
from dotenv import load_dotenv

logging.basicConfig(level=logging.DEBUG)

async def main():
    load_dotenv()
    print("🚀 Starting AI Payload Generation Test...")
    
    # Needs GEMINI_API_KEY to be set in environment for AI generation to work.
    if not os.getenv("GEMINI_API_KEY"):
        print("⚠️ GEMINI_API_KEY is not set. The engine will fallback to heuristic payloads.")
    else:
        print("✅ GEMINI_API_KEY found. AI Generation will execute.")
        
    config = EngineConfig(engine_id="advanced_payload", max_payloads=10, custom_params={"mutation_level": 3})
    adapter = AdvancedPayloadAdapter(config)
    
    vectors = [
        {
            "endpoint": "/api/user",
            "parameter": "id",
            "payloads": ["1"]
        }
    ]
    
    print("📡 Probing target http://127.0.0.1:8081...")
    findings = await adapter.scan("http://127.0.0.1:8081", vectors)
    
    print("\n[+] Scan Complete")
    print(f"[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"  - Vulnerability: {f.type.value}")
        print(f"  - Payload: {f.payload}")
        print(f"  - Confidence: {f.confidence}")
        
    print("\n[+] Adapter Status:")
    print(adapter.get_status())

if __name__ == "__main__":
    asyncio.run(main())
