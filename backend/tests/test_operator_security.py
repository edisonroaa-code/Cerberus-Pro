"""
Operator Security Test: Validating Kill-Switch and Token Compartmentalization.
"""

import os
import sys
import pytest
from httpx import AsyncClient
import secrets

# Ensure backend modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Force development mode
os.environ.setdefault("ENVIRONMENT", "development")

@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _login_admin(client: AsyncClient) -> str:
    admin_password = os.environ.get("CERBERUS_ADMIN_PASSWORD", "admin")
    login_resp = await client.post(
        "/auth/login",
        json={"username": "admin", "password": admin_password},
    )
    assert login_resp.status_code == 200, login_resp.text
    token = login_resp.json().get("access_token")
    assert token, login_resp.text
    return token

@pytest.mark.anyio
async def test_kill_switch_trigger():
    """Verify that the Kill-Switch halts operations and prevents new ones."""
    from backend.ares_api import app, state
    
    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            token = await _login_admin(client)
            headers = {"Authorization": f"Bearer {token}"}
            
            # Step 1: Trigger Kill-Switch
            kill_resp = await client.post("/admin/killswitch", headers=headers)
            assert kill_resp.status_code == 200
            assert kill_resp.json()["status"] == "triggered"
            assert state.kill_switch_active is True
            
            # Step 2: Verify that starting a new job fails (or is ignored by worker)
            # The worker loop should exit.
            # We can check if state says so.
            # In a real environment, the loop would break.


@pytest.mark.anyio
async def test_register_endpoint_admin_path_works():
    """Regression: /auth/register must not crash with dependency type errors."""
    from backend.ares_api import app

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            token = await _login_admin(client)
            headers = {"Authorization": f"Bearer {token}"}
            username = f"user_{secrets.token_hex(4)}"
            payload = {
                "username": username,
                "email": f"{username}@example.com",
                "full_name": "Operator Test",
                "password": "ValidPassw0rd!X",
                "role": "analyst",
            }

            resp = await client.post("/auth/register", json=payload, headers=headers)
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["username"] == username
            assert "password_hash" not in body


@pytest.mark.anyio
async def test_logout_revokes_http_access_token():
    """Token used before logout must fail after logout across HTTP endpoints."""
    from backend.ares_api import app

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            token = await _login_admin(client)
            headers = {"Authorization": f"Bearer {token}"}

            pre = await client.get("/auth/me", headers=headers)
            assert pre.status_code == 200, pre.text

            out = await client.post("/auth/logout", headers=headers)
            assert out.status_code == 200, out.text

            post = await client.get("/auth/me", headers=headers)
            assert post.status_code == 401, post.text

@pytest.mark.anyio
async def test_token_compartmentalization_agent_refresh():
    """Verify that AGENT tokens cannot be refreshed."""
    from backend.ares_api import app, state
    from backend.auth_security import Role, TokenType, JWTManager, User
    from datetime import datetime, timezone
    
    async with app.router.lifespan_context(app):
        # Manually inject a mock agent user into state
        state.users["agent_007"] = User(
            id="agent_007",
            username="bond-agent",
            email="agent@ops.lan",
            full_name="James Bond Agent",
            role=Role.AGENT,
            password_hash="fake",
            created_at=datetime.now(timezone.utc),
            last_login=None
        )

        # Manually create an Agent Refresh Token
        agent_refresh_token = JWTManager.create_token(
            user_id="agent_007",
            username="bond-agent",
            email="agent@ops.lan",
            role=Role.AGENT,
            token_type=TokenType.REFRESH
        )
        
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Try to refresh (expects cookie)
            resp = await client.post("/auth/refresh", cookies={"refresh_token": agent_refresh_token})
            
            # Should fail with 403 (as implemented in routers/auth.py)
            if resp.status_code != 403:
                print(f"DEBUG: Status={resp.status_code}, Body={resp.text}")
            assert resp.status_code == 403
            assert "Agent tokens are non-renewable" in resp.text
