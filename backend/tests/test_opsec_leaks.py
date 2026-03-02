"""
OPSEC Leak Test: Automated verification that sensitive data is NEVER leaked in API responses.
"""

import os
import sys
import pytest
from httpx import AsyncClient

# Ensure backend modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Force development mode
os.environ.setdefault("ENVIRONMENT", "development")

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.mark.anyio
async def test_no_sensitive_leaks_in_auth_response():
    """Verify that auth-related responses don't contain hashes or secrets."""
    from backend.ares_api import app
    
    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Test 1: Login
            resp = await client.post("/auth/login", json={"username": "admin", "password": "admin"})
            assert resp.status_code == 200
            content = resp.text
            
            # Blacklist of sensitive strings
            blacklist = [
                "password_hash",
                "mfa_secret",
                "mfa_encryption_key",
                "encryption_key",
                "jwt_secret",
                "$2b$12$", # Typical bcrypt prefix
            ]
            
            for word in blacklist:
                assert word not in content.lower(), f"🚨 OPSEC LEAK: Found '{word}' in login response"

@pytest.mark.anyio
async def test_no_sensitive_leaks_in_audit_logs():
    """Verify that audit logs don't contain sensitive data."""
    from backend.ares_api import app
    
    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Login to get token
            login_resp = await client.post("/auth/login", json={"username": "admin", "password": "admin"})
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            # Fetch audit logs
            resp = await client.get("/admin/audit-logs", headers=headers)
            assert resp.status_code == 200
            content = resp.text
            
            blacklist = ["password_hash", "mfa_secret", "encryption_key"]
            for word in blacklist:
                assert word not in content.lower(), f"🚨 OPSEC LEAK: Found '{word}' in audit logs"

@pytest.mark.anyio
async def test_no_sensitive_leaks_in_agent_registration():
    """Verify that agent registration doesn't leak system keys."""
    from backend.ares_api import app
    
    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Login as admin to be allowed to create agents
            login_resp = await client.post("/auth/login", json={"username": "admin", "password": "admin"})
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            resp = await client.post("/c2/agents/create", json={
                "agent_name": "test-agent-opsec"
            }, headers=headers)
            
            assert resp.status_code == 200
            content = resp.text
            assert "encryption_key" not in content.lower(), "🚨 OPSEC LEAK: encryption_key found in agent registration"
            assert "client_secret_hash" not in content.lower(), "🚨 OPSEC LEAK: secret hash found in agent registration"
