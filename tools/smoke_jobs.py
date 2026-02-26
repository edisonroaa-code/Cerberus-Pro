import asyncio
import json
import os
import sys

import httpx


async def main() -> int:
    # Ensure repo root is importable when running from anywhere.
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    # In-process smoke test (no uvicorn needed).
    from backend.ares_api import app

    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        # TrustedHostMiddleware blocks unknown Host headers; use 127.0.0.1 for smoke.
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            # Default admin created at startup in lifespan
            login = await client.post(
                "/auth/login",
                json={"username": "admin", "password": "CerberusPro2024!", "mfa_code": None},
            )
            if login.status_code != 200:
                print("LOGIN_FAIL", login.status_code, login.text)
                return 2

            # Queue a job (target chosen to be stable and non-sensitive).
            # NOTE: This may still fail fast (policy, spawn, etc.) which is acceptable for smoke.
            payload = {
                "config": {
                    "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
                    "profile": "Corporativo-Sigiloso",
                    "autoPilot": False,
                    "aggressionLevel": 3,
                    "sqlMap": {
                        "threads": 1,
                        "level": 1,
                        "risk": 1,
                        "technique": "BEUSTQ",
                        "hpp": False,
                        "hex": False,
                        "timeout": 10,
                    },
                    "unified": {
                        "vectors": ["BOOLEAN", "ERROR", "TIME", "UNION"],
                        "maxParallel": 2,
                    },
                }
            }
            start = await client.post("/scan/start", json=payload)
            if start.status_code != 200:
                print("START_FAIL", start.status_code, start.text)
                return 3
            data = start.json()
            scan_id = data.get("scan_id")
            if not scan_id:
                print("NO_SCAN_ID", json.dumps(data, indent=2))
                return 4
            print("QUEUED", scan_id)

            # Poll until the worker flips state (running/failed/completed/stopped/interrupted).
            terminal = {"completed", "failed", "stopped", "interrupted"}
            last = None
            for _ in range(60):
                job = await client.get(f"/jobs/{scan_id}")
                if job.status_code != 200:
                    print("JOB_GET_FAIL", job.status_code, job.text)
                    return 5
                j = job.json()
                st = str(j.get("status") or "")
                if st != last:
                    print("STATUS", st)
                    last = st
                if st in terminal:
                    break
                await asyncio.sleep(1)

            job = (await client.get(f"/jobs/{scan_id}")).json()
            print(
                "FINAL",
                json.dumps(
                    {k: job.get(k) for k in ["scan_id", "kind", "status", "pid", "result_filename", "error"]},
                    indent=2,
                ),
            )
            return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
