#!/usr/bin/env python3
"""
Recall guardrails.

Fails CI if deprecated runtime patterns are reintroduced.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def main() -> int:
    errors: list[str] = []

    package_path = ROOT / "package.json"
    package = json.loads(read_text(package_path))
    scripts = package.get("scripts", {})
    canonical_targets = (
        "backend",
        "backend:lan",
        "dev:core",
        "dev:core:lan",
        "dev:all:full",
        "dev:all:full:lan",
    )
    for name in canonical_targets:
        cmd = str(scripts.get(name, ""))
        if "backend.ares_api:app" not in cmd:
            errors.append(f"script '{name}' must target backend.ares_api:app")
        if "backend.cerberus_pro_api_secure:app" in cmd:
            errors.append(f"script '{name}' must not target deprecated compatibility facade")

    dockerfile = read_text(ROOT / "backend" / "Dockerfile")
    if "backend.ares_api:app" not in dockerfile:
        errors.append("backend/Dockerfile must target backend.ares_api:app")
    if "backend.cerberus_pro_api_secure:app" in dockerfile:
        errors.append("backend/Dockerfile must not target deprecated compatibility facade")

    compose_file = read_text(ROOT / "docker-compose.yml")
    if "backend.ares_api:app" not in compose_file:
        errors.append("docker-compose.yml api command must target backend.ares_api:app")
    if "backend.cerberus_pro_api_secure:app" in compose_file:
        errors.append("docker-compose.yml must not target deprecated compatibility facade")

    launcher = read_text(ROOT / "start_ares.py")
    if "backend.ares_api:app" not in launcher:
        errors.append("start_ares.py must target backend.ares_api:app")
    if "backend.cerberus_pro_api_secure:app" in launcher:
        errors.append("start_ares.py must not target deprecated compatibility facade")

    app_tsx = read_text(ROOT / "App.tsx")
    if "${API_BASE_URL}/start" in app_tsx:
        errors.append("App.tsx must not call legacy /start endpoint")
    if "${API_BASE_URL}/stop" in app_tsx:
        errors.append("App.tsx must not call legacy /stop endpoint")
    if "parts[1] === 'omni'" in app_tsx:
        errors.append("App.tsx terminal command parser must not accept legacy 'omni' token")

    router_scan = read_text(ROOT / "backend" / "routers" / "scan.py")
    if '@router.get("/status")' in router_scan:
        errors.append("backend/routers/scan.py must not expose @router.get('/status')")
    if '@router.get("/module/status")' not in router_scan:
        errors.append("backend/routers/scan.py must expose @router.get('/module/status')")

    ares_api = read_text(ROOT / "backend" / "ares_api.py")
    if "state.omni_tasks" in ares_api:
        errors.append("backend/ares_api.py must not reference deprecated state.omni_tasks")
    if "from core.scan_manager import ScanManager" in ares_api:
        errors.append("backend/ares_api.py must not import legacy ScanManager fallback")
    if "ScanManager(" in ares_api:
        errors.append("backend/ares_api.py must not execute ScanManager fallback in unified runtime")
    if "OrchestratorPhase.ESCALATION" not in ares_api:
        errors.append("backend/ares_api.py unified runner must include ESCALATION phase")
    if "from routers.scan import router as scan_router" in ares_api:
        errors.append("backend/ares_api.py must not import legacy scan router facade")
    if "app.include_router(scan_router" in ares_api:
        errors.append("backend/ares_api.py must not include legacy scan router facade")
    if "/scan/omni/" in ares_api:
        errors.append("backend/ares_api.py must not expose /scan/omni/* compatibility aliases in hard-break mode")

    backend_root = ROOT / "backend"
    legacy_root_blocklist = (
        "patch_api.py",
        "patch_api_2026.py",
        "patch_api_stability.py",
        "tmp_cors_patch.py",
        "inject_endpoint.py",
        "diagnostic_v4.py",
        "verify_v4_omni.py",
        "verify_2026_evasion.py",
        "check_pg.py",
        "validate_sqlmap_fix.py",
        "test_grpc_fuzzer.py",
        "test_v4_advanced.py",
        "ARCHITECTURE_DIAGRAMS.md",
        "GETTING_STARTED.md",
        "INDEX.md",
        "POSTGRES_SETUP.md",
        "ROADMAP_OFENSIVO_2026-2027.md",
        "VERDICT_ENGINE_ARCHITECTURE.md",
        "VERDICT_ENGINE_QUICKSTART.md",
        "example_integration.py",
        "main.py",
        "cerberus_pro_api.py",
        "cerberus_ci.py",
    )
    for name in legacy_root_blocklist:
        if (backend_root / name).exists():
            errors.append(f"legacy file must stay archived, found: backend/{name}")

    project_root_blocklist = (
        "AGENT_INTEGRATION.md",
        "AUDIT_QUESTIONNAIRE_EVIDENCE.md",
        "CERBERUS_PRO_README.md",
        "CHANGELOG.md",
        "DEPLOYMENT_GUIDE.md",
        "EXPORT_SOURCE.md",
        "FASE1_IMPLEMENTACION.md",
        "INDEX.md",
        "LANZAMIENTO_OFICIAL.md",
        "QUICKSTART.md",
        "RESUMEN_EJECUTIVO.md",
        "RESUMEN_ENTREGA.md",
        "ROADMAP_SEGURIDAD_AVANZADA.md",
        "ROADMAP_V4.md",
        "SECURITY_CHECKLIST_FASE1.md",
        "TRANSFORMACION_COMPLETA.md",
        "App_Secure.tsx",
        "cerberus_pro_api_secure.py",
        "backend.log",
        "cerberus_source_export.zip",
    )
    for name in project_root_blocklist:
        if (ROOT / name).exists():
            errors.append(f"legacy root doc must stay archived, found: {name}")

    if errors:
        print("Recall guard failed:")
        for e in errors:
            print(f"- {e}")
        return 1

    print("Recall guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
