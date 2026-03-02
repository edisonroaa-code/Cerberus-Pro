import asyncio
import os
import sys
import time
import logging
from typing import Dict, Any, List, Optional, Callable
from aiohttp import web
from dataclasses import dataclass

# Add backend and root directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
root_dir = os.path.abspath(os.path.join(backend_dir, '..'))
sys.path.insert(0, backend_dir)
sys.path.insert(0, root_dir)

from backend.v4_omni_surface import engine_registry, OmniResult, run_sqlmap_vector
from backend.core.cerberus_http_client import CerberusHTTPClient

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("diagnostic_all_engines")

# --- Mock Vulnerable Server ---
async def handle_sqli(request):
    """Boolean, Error and Union based SQLi endpoint with exfiltration support"""
    id_param = str(request.query.get('id', ''))
    
    # 1. AIIE Latency Trigger (PRIORITY)
    # If it looks like a lethal payload attempt (OR, CASE, SLEEP), introduce latency
    if "OR" in id_param.upper() or "CASE" in id_param.upper() or "SLEEP" in id_param.upper():
        await asyncio.sleep(4) # Clear trigger for AIIE z-score > 5
        return web.json_response({
            "status": "vulnerable_hit",
            "data": "Data accessed via intelligent bypass",
            "db": "cerberus_vault"
        })

    # 2. Information Schema / Extraction (Table Discovery)
    if "SELECT" in id_param.upper() or "INFO_SCHEMA" in id_param.upper() or "TABLE_NAME" in id_param.upper() or "USER" in id_param.upper():
        return web.json_response({
            "status": "leaked",
            "tables": ["users", "admin_creds", "v4_config_vault"],
            "user": "root_cerberus",
            "database": "ghost_db",
            "version": "v15.2-1"
        })

    # 3. Error-based
    if "'" in id_param and "UNION" not in id_param.upper():
        return web.Response(text="SQL error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server", status=500)
    
    # 4. Boolean-based
    if "1=1" in id_param or "1%3D1" in id_param.upper():
        return web.json_response({"status": "found", "data": "Secret User Data"})
    
    # 5. Union-based Marker
    if "CERBERUS_PRO_NATIVE_UNION" in id_param:
        return web.Response(text="[DEBUG] Result: CERBERUS_PRO_NATIVE_UNION detected in stream")

    return web.json_response({"status": "default", "data": "Regular User Content"})

async def handle_ssti(request):
    """SSTI endpoint (Jinja2 style)"""
    test_param = request.query.get('test', '')
    if "{{7*7}}" in test_param:
        return web.Response(text="Result is 49")
    return web.Response(text=f"Echo: {test_param}")

async def setup_server():
    app = web.Application()
    app.router.add_get('/vuln/sqli', handle_sqli)
    app.router.add_get('/vuln/ssti', handle_ssti)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 8888)
    await site.start()
    return runner

# --- Test Execution ---
async def run_diagnostic():
    server_runner = await setup_server()
    logger.info("✅ Mock vulnerable server started at 127.0.0.1:8888")
    
    target_sqli = "http://127.0.0.1:8888/vuln/sqli?id=1"
    target_ssti = "http://127.0.0.1:8888/vuln/ssti"
    
    async def mock_broadcast(component, level, msg, metadata=None):
        print(f"[{component}] {level}: {msg}")

    # Initialize Anonymized Client (Localhost for testing, no TOR)
    anon_client = CerberusHTTPClient(use_tor=False)
    
    results = []

    try:
        # 1. Test AIIE Engine (Predatory Mode + Extraction)
        logger.info("\n--- ⚡ Testing AIIE Engine (Predatory + Extraction) ---")
        aiie = engine_registry.get_engine("aiie")
        if aiie:
            # We force a risk_level that triggers extraction
            res = await aiie.run(target_sqli, {"risk_level": 2}, mock_broadcast, client=anon_client)
            results.append(res)
            logger.info(f"AIIE Status: {'VULNERABLE' if res.vulnerable else 'SAFE'}")
            if res.loot:
                logger.info(f"✅ AIIE LOOT DETECTED: {list(res.loot.keys())}")

        # 2. Test SSTI Engine
        logger.info("\n--- 🧩 Testing SSTI Engine ---")
        ssti = engine_registry.get_engine("ssti")
        if ssti:
            res = await ssti.run(target_ssti, {}, mock_broadcast, client=anon_client)
            results.append(res)
            logger.info(f"SSTI Status: {'VULNERABLE' if res.vulnerable else 'SAFE'}")

        # 3. Test Native Union Vector (Table Discovery Support)
        logger.info("\n--- 🚀 Testing Native Union Vector ---")
        cmd_union = ["python", "sqlmap.py", "-u", target_sqli, "--technique=U"]
        res_union = await run_sqlmap_vector("UNION_NATIVE", cmd_union, mock_broadcast)
        results.append(res_union)
        logger.info(f"Union Native Status: {'VULNERABLE' if res_union.vulnerable else 'SAFE'}")

        # 4. Test Native Boolean Vector
        logger.info("\n--- 🚀 Testing Native Boolean Vector ---")
        cmd_boolean = ["python", "sqlmap.py", "-u", target_sqli, "--technique=B"]
        res_boolean = await run_sqlmap_vector("BOOLEAN_NATIVE", cmd_boolean, mock_broadcast)
        results.append(res_boolean)
        logger.info(f"Boolean Native Status: {'VULNERABLE' if res_boolean.vulnerable else 'SAFE'}")

    finally:
        await anon_client.close()
        await server_runner.cleanup()
        logger.info("✅ Mock server stopped.")

    print("\n" + "="*40)
    print("      DIAGNOSTIC SUMMARY")
    print("="*40)
    for r in results:
        status = "VULN" if r.vulnerable else "SAFE"
        print(f"{r.vector:<15}: {status} | Evidence: {bool(r.evidence)}")
    print("="*40)

if __name__ == "__main__":
    asyncio.run(run_diagnostic())
