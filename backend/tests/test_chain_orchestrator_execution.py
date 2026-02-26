import asyncio

from backend.core.chain_orchestrator_v2 import ChainOrchestratorV2
from backend.engines.base import EngineAdapter, EngineConfig, Finding, VulnerabilityType, Severity, register_engine


class DummyEngine(EngineAdapter):
    def __init__(self, engine_id: str, return_count: int = 1):
        cfg = EngineConfig(engine_id=engine_id)
        super().__init__(cfg)
        self.return_count = return_count

    async def scan(self, target: str, vectors: list):
        # Produce synthetic findings list of length return_count
        findings = []
        for i in range(self.return_count):
            f = Finding(
                type=VulnerabilityType.SQL_INJECTION,
                endpoint=vectors[0]["endpoint"],
                parameter=vectors[0]["parameter"],
                payload=vectors[0].get("payloads", [""])[0],
                confidence=0.8,
                severity=Severity.MEDIUM,
                evidence="synthetic",
                engine=self.config.engine_id,
            )
            findings.append(f)
        return findings

    def get_status(self):
        return {"engine": self.config.engine_id, "status": "ready"}

    async def stop(self):
        return


def test_run_chain_async_with_engines(monkeypatch):
    # register two dummy engines
    import backend.engines.base as base

    base._engines.clear()
    e1 = DummyEngine("engine_sql", return_count=1)
    e2 = DummyEngine("engine_payload", return_count=0)  # will simulate failure (no findings)
    register_engine(e1.config.engine_id, e1)
    register_engine(e2.config.engine_id, e2)

    chain = {
        "name": "test_chain",
        "base_cvss": 7.0,
        "steps": [
            {"id": "s1", "description": "Test SQLi", "engine": "engine_sql"},
            {"id": "s2", "description": "Payload probe", "engine": "engine_payload"},
        ],
    }

    orch = ChainOrchestratorV2()
    vectors = [{"endpoint": "/", "parameter": "id", "payloads": ["1' OR 1=1"]}]

    result = asyncio.run(orch.run_chain_async(chain, "http://example", vectors))

    assert result["chain"] == "test_chain"
    assert isinstance(result["score"], float)
    assert len(result["steps"]) == 2
    # first step should be ok (engine_sql returned 1 finding), second step not ok
    assert result["steps"][0]["ok"] is True
    assert result["steps"][1]["ok"] is False
    assert result["success"] is False
