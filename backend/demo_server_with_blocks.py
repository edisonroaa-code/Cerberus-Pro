#!/usr/bin/env python3
"""
Mock vulnerable target server with intermittent 502/503 blocks.
Simulates WAF behavior: allows initial probe, then blocks some requests mid-stream.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Optional
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

app = FastAPI()

# Simple state tracking
request_count = 0
vulnerable_param = "id"
db_name = "target_db"
current_user = "www-data"
block_after_request = 7  # Block after 7 requests to simulate mid-stream detection


@app.get("/")
async def root():
    """Health check."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/test")
async def test_endpoint(request: Request, id: Optional[str] = Query(None)):
    """
    Vulnerable endpoint that simulates SQLi detection and intermittent blocking.
    - First few requests: return mock vulnerable responses
    - After request N: simulate WAF block (502/503)
    - Respond to extraction queries (--current-db, --dbs) with data
    """
    global request_count
    request_count += 1
    
    # Get client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    cookie_header = request.headers.get("cookie", "")
    accept_header = request.headers.get("accept", "")
    
    # Log the request with all relevant details
    log_entry = {
        "request_number": request_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "user_agent": user_agent[:80],
        "has_cookie": bool(cookie_header),
        "accept_header": accept_header[:80],
        "param_id": str(id)[:50] if id else None,
    }
    
    # Simulate intermittent 502/503 after N requests
    if request_count > block_after_request and request_count % 3 == 0:
        log_entry["response"] = "502_simulated_block"
        log_entry["reason"] = "WAF_ACTIVE_BLOCKING"
        print(f"[{request_count:3d}] BLOCK 502: {user_agent[:40]:40} | Cookie: {bool(cookie_header)} | {id}")
        return JSONResponse(
            {"error": "Bad Gateway", "detail": "Request blocked by WAF"},
            status_code=502,
            headers={"X-WAF": "SIM_ACTIVE", "X-Block-Reason": "injection_payload_detected"}
        )
    
    # Simulate 503 occasionally
    if request_count > block_after_request + 2 and request_count % 5 == 1:
        log_entry["response"] = "503_service_unavailable"
        print(f"[{request_count:3d}] BLOCK 503: {user_agent[:40]:40} | Cookie: {bool(cookie_header)} | {id}")
        return JSONResponse(
            {"error": "Service Unavailable"},
            status_code=503,
        )
    
    # Normal response: simulate SQLi vulnerability
    if id:
        # Check for extraction queries (--current-db, --dbs, etc.)
        if "version" in id.lower() or "@@version" in id.lower():
            log_entry["response"] = "mysql_version_info"
            response_text = f"MySQL 5.7.32-0ubuntu0.18.04.1\nServer: MySQL\n"
            print(f"[{request_count:3d}] INJECT OK (version): {user_agent[:40]:40} -> version info returned")
            return PlainTextResponse(response_text, status_code=200)
        
        if "database()" in id.lower() or "current_db" in id.lower():
            log_entry["response"] = "current_database_info"
            response_text = f"\nCurrent database: {db_name}\n"
            print(f"[{request_count:3d}] INJECT OK (db): {user_agent[:40]:40} -> {db_name}")
            return PlainTextResponse(response_text, status_code=200)
        
        if "user()" in id.lower() or "current_user" in id.lower():
            log_entry["response"] = "current_user_info"
            response_text = f"\nCurrent user: {current_user}@localhost\n"
            print(f"[{request_count:3d}] INJECT OK (user): {user_agent[:40]:40} -> {current_user}")
            return PlainTextResponse(response_text, status_code=200)
        
        # Generic SQLi response
        if "1" in id or "'" in id:
            log_entry["response"] = "vulnerable_true"
            response_text = f"<html><body>User ID: {id} | Status: OK</body></html>\n"
            print(f"[{request_count:3d}] INJECT OK: {user_agent[:40]:40} | Cookie: {bool(cookie_header)}")
            return PlainTextResponse(response_text, status_code=200)
    
    # No params: show form
    log_entry["response"] = "form_page"
    html = f"""
    <html>
    <head><title>Test Form</title></head>
    <body>
        <h1>Vulnerable Test Form</h1>
        <form method="GET" action="/test">
            <label>User ID:</label>
            <input type="text" name="id" value="1" />
            <button type="submit">Submit</button>
        </form>
        <p>Request count: {request_count}</p>
    </body>
    </html>
    """
    return PlainTextResponse(html, status_code=200)


if __name__ == "__main__":
    print("[DEMO_SERVER] Starting vulnerable test server on http://127.0.0.1:8888")
    print(f"[DEMO_SERVER] Will simulate WAF blocks after request #{block_after_request}")
    print("[DEMO_SERVER] Accessible at http://127.0.0.1:8888/test?id=1")
    print()
    uvicorn.run(app, host="127.0.0.1", port=8888, log_level="critical")
