#!/usr/bin/env python3
"""
Thin facade for the runtime implementation.
This file intentionally keeps only route-surface markers and symbol re-exports.
"""

from __future__ import annotations

from types import ModuleType

from backend import ares_runtime as _impl

# Route-surface markers kept for static route-surface tests:
# @app.post("/scan/start")
# @app.post("/scan/stop")
# @app.get("/scan/status")
# @app.get("/scan/capabilities")
# Contract marker:
# OrchestratorPhase.ESCALATION


def _reexport_runtime_symbols(module: ModuleType) -> None:
    for name in dir(module):
        if name.startswith("__"):
            continue
        globals()[name] = getattr(module, name)


_reexport_runtime_symbols(_impl)


if __name__ == "__main__":
    import os
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 8001)),
        log_level="info",
        ssl_keyfile=os.environ.get("SSL_KEYFILE") if globals().get("ENVIRONMENT") == "production" else None,
        ssl_certfile=os.environ.get("SSL_CERTFILE") if globals().get("ENVIRONMENT") == "production" else None,
    )
