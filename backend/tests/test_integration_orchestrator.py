import asyncio

from backend.engines.orchestrator import EngineOrchestrator
from backend.engines.base import (
    EngineAdapter,
    EngineConfig,
    Finding,
    VulnerabilityType,
    Severity,
    register_engine,
)


class FakeEngine(EngineAdapter):
    def __init__(self, engine_id: str):
        cfg = EngineConfig(engine_id=engine_id)
        super().__init__(cfg)
        self.observed_custom_params = None

    async def scan(self, target: str, vectors: list) -> list:
        # Record the custom params at scan-time for assertions
        self.observed_custom_params = dict(self.config.custom_params or {})
        # Return a single synthetic finding
        f = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint=vectors[0]["endpoint"],
            parameter=vectors[0]["parameter"],
            payload=vectors[0].get("payloads", [""])[0],
            confidence=0.9,
            severity=Severity.HIGH,
            evidence="synthetic",
            engine=self.config.engine_id,
        )
        return [f]

    def get_status(self):
        return {"engine": self.config.engine_id, "status": "ready"}

    async def stop(self):
        return


def test_orchestrator_applies_waf_strategies(monkeypatch):
    # Clear and register two fake engines
    import backend.engines.base as base

    base._engines.clear()

    e1 = FakeEngine("fake_sql")
    e2 = FakeEngine("fake_payload")

    register_engine("fake_sql", e1)
    register_engine("fake_payload", e2)

    # Patch waf_detective.fingerprint to return Cloudflare
    async def _fp(target, timeout=5):
        return {"waf": "Cloudflare", "evidence": "server:cloudflare"}

    monkeypatch.setattr("backend.core.waf_detective.fingerprint", _fp)

    orch = EngineOrchestrator()

    vectors = [{"endpoint": "/","parameter": "id", "payloads": ["1' OR '1'='1"]}]

    results = asyncio.run(orch.scan_all("http://example.com", vectors))

    # We should have findings from both engines (dedup might combine, but at least one)
    assert isinstance(results, list)
    assert any(f.engine == "fake_sql" or f.engine == "fake_payload" for f in results)

    # Verify that strategies were applied (double_encode and extra_params should be set)
    assert e1.observed_custom_params is not None
    assert e2.observed_custom_params is not None
    assert e1.observed_custom_params.get("double_encode") is True
    assert e2.observed_custom_params.get("extra_params", {}).get("cerberus_noise") == "1"
