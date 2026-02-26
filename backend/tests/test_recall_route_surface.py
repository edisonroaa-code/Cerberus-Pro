from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def test_legacy_start_stop_routes_not_declared():
    src = _read(ROOT / "backend" / "ares_api.py")
    assert '@app.post("/start")' not in src
    assert '@app.post("/stop")' not in src


def test_canonical_scan_routes_declared():
    src = _read(ROOT / "backend" / "ares_api.py")
    assert '@app.post("/scan/start")' in src
    assert '@app.post("/scan/stop")' in src
    assert '@app.get("/scan/status")' in src
    assert '@app.get("/scan/capabilities")' in src
    assert '/scan/omni/start' not in src
    assert '/scan/omni/stop' not in src
    assert '/scan/omni/status' not in src
    assert '/scan/omni/capabilities' not in src


def test_modular_scan_status_path_moved_to_module_namespace():
    router_src = _read(ROOT / "backend" / "routers" / "scan.py")
    assert '@router.get("/module/status")' in router_src
    assert '@router.get("/status")' not in router_src


def test_unified_runtime_has_no_scan_manager_fallback():
    src = _read(ROOT / "backend" / "ares_api.py")
    assert "from core.scan_manager import ScanManager" not in src
    assert "ScanManager(" not in src


def test_unified_runtime_has_no_legacy_scan_router_facade():
    src = _read(ROOT / "backend" / "ares_api.py")
    assert "from routers.scan import router as scan_router" not in src
    assert "app.include_router(scan_router" not in src


def test_unified_runtime_includes_escalation_phase():
    src = _read(ROOT / "backend" / "ares_api.py")
    assert "OrchestratorPhase.ESCALATION" in src
