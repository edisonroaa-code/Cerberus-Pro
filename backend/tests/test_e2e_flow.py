"""
E2E Integration Test: Auth → Jobs → History flow.

Validates the full user journey through the Cerberus Pro API
using httpx.AsyncClient with ASGITransport (no real network needed).
"""

import os
import sys
import pytest

# Ensure backend modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Force development mode so admin has default password
os.environ.setdefault("ENVIRONMENT", "development")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def login_payload():
    """Default admin credentials for dev mode."""
    return {"username": "admin", "password": "admin"}


@pytest.mark.anyio
async def test_login_returns_token(login_payload):
    """POST /auth/login should return an access_token."""
    from httpx import AsyncClient, ASGITransport

    try:
        from ares_api import app  # type: ignore
    except ImportError:
        from backend.ares_api import app  # type: ignore

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            resp = await client.post("/auth/login", json=login_payload)

    assert resp.status_code == 200, f"Login failed: {resp.text}"
    data = resp.json()
    assert "access_token" in data, "Missing access_token in login response"
    assert len(data["access_token"]) > 20, "Token seems too short"


@pytest.mark.anyio
async def test_jobs_list_requires_auth():
    """GET /jobs without a token should return 401 or 403."""
    from httpx import AsyncClient, ASGITransport

    try:
        from ares_api import app  # type: ignore
    except ImportError:
        from backend.ares_api import app  # type: ignore

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            resp = await client.get("/jobs")

    assert resp.status_code in (401, 403), f"Expected auth error, got {resp.status_code}"


@pytest.mark.anyio
async def test_authenticated_jobs_list(login_payload):
    """GET /jobs with a valid token should return 200."""
    from httpx import AsyncClient, ASGITransport

    try:
        from ares_api import app  # type: ignore
    except ImportError:
        from backend.ares_api import app  # type: ignore

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Step 1: Login
            login_resp = await client.post("/auth/login", json=login_payload)
            assert login_resp.status_code == 200
            token = login_resp.json()["access_token"]

            # Step 2: List jobs with bearer token
            headers = {"Authorization": f"Bearer {token}"}
            jobs_resp = await client.get("/jobs", headers=headers)

    assert jobs_resp.status_code == 200, f"Jobs list failed: {jobs_resp.text}"


@pytest.mark.anyio
async def test_history_list_authenticated(login_payload):
    """GET /history should return a list (possibly empty) when authenticated."""
    from httpx import AsyncClient, ASGITransport

    try:
        from ares_api import app  # type: ignore
    except ImportError:
        from backend.ares_api import app  # type: ignore

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Step 1: Login
            login_resp = await client.post("/auth/login", json=login_payload)
            assert login_resp.status_code == 200
            token = login_resp.json()["access_token"]

            # Step 2: List history
            headers = {"Authorization": f"Bearer {token}"}
            hist_resp = await client.get("/history", headers=headers)

    assert hist_resp.status_code == 200, f"History list failed: {hist_resp.text}"
    assert isinstance(hist_resp.json(), list), "History should return a list"


@pytest.mark.anyio
async def test_full_e2e_login_jobs_history(login_payload):
    """Full E2E: login → list jobs → list history → verify health."""
    from httpx import AsyncClient, ASGITransport

    try:
        from ares_api import app  # type: ignore
    except ImportError:
        from backend.ares_api import app  # type: ignore

    async with app.router.lifespan_context(app):
        from httpx import ASGITransport
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # 1. Health check (requires auth now)
            health_resp = await client.get("/health")
            assert health_resp.status_code == 401, "Expected 401 for unauthenticated health"

            # 2. Login
            login_resp = await client.post("/auth/login", json=login_payload)
            assert login_resp.status_code == 200
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # 2b. Health check (authenticated)
            health_resp = await client.get("/health", headers=headers)
            assert health_resp.status_code == 200, "Health endpoint failed with auth"

            # 3. List jobs
            jobs_resp = await client.get("/jobs", headers=headers)
            assert jobs_resp.status_code == 200

            # 4. List history
            hist_resp = await client.get("/history", headers=headers)
            assert hist_resp.status_code == 200
            assert isinstance(hist_resp.json(), list)

            # 5. Metrics
            metrics_resp = await client.get("/metrics", headers=headers)
            assert metrics_resp.status_code == 200
