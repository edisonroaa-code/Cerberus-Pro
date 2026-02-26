"""
Surface endpoint payload helpers extracted from ares_api.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.responses import Response


@dataclass
class ApiSurfaceOpsDeps:
    omni_allowed_modes: set[str]
    omni_allowed_vectors: set[str]
    running_kind_values: Iterable[Any]
    normalize_job_kind_fn: Callable[[Any], str]
    canonical_job_kind: str
    active_omni_scans_metric: Any
    generate_latest_fn: Callable[[], bytes]
    content_type_latest: str
    logger: Any
    browser_stealth_cls: Any


def scan_capabilities_payload(deps: ApiSurfaceOpsDeps) -> Dict[str, Any]:
    return {
        "modes": sorted(list(deps.omni_allowed_modes)),
        "vectors": sorted(list(deps.omni_allowed_vectors)),
        "limits": {
            "max_parallel_min": 1,
            "max_parallel_max": 8,
        },
        "notes": {
            "grpc": "Deep fuzzing active (Reflection + Discovery)",
            "nosql": "MongoDB & Redis injection patterns",
            "evasion_2026": "Cloudflare/Akamai/AWS specific presets active",
            "ssti": "Template injection probes (Jinja2, Twig, etc.)",
            "oob": "DNS/ICMP tunneling implemented via sqlmap backend",
            "pivoting": "Tor & Proxy support active",
            "chaining": "Automatic environment extraction after confirmed vuln",
        },
    }


def metrics_payload(deps: ApiSurfaceOpsDeps) -> Response:
    worker_based = sum(
        1 for kind in deps.running_kind_values if deps.normalize_job_kind_fn(kind) == deps.canonical_job_kind
    )
    deps.active_omni_scans_metric.set(int(worker_based))
    return Response(content=deps.generate_latest_fn(), media_type=deps.content_type_latest)


async def setup_playwright_payload(*, username: str, deps: ApiSurfaceOpsDeps) -> Dict[str, Any]:
    deps.logger.info("Playwright setup triggered by %s", username)
    success = await deps.browser_stealth_cls.ensure_browsers()
    if success:
        return {"message": "Navegadores instalados exitosamente"}
    raise HTTPException(status_code=500, detail="Fallo en la instalacion de navegadores")


def http_exception_payload(exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "timestamp": datetime.now(timezone.utc).isoformat()},
    )
