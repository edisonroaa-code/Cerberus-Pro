import asyncio

from backend.engines.orchestrator import EngineOrchestrator
from backend.engines.base import EngineConfig, EngineAdapter, Finding, VulnerabilityType, Severity, register_engine


class SimpleEngine(EngineAdapter):
    def __init__(self, engine_id: str, findings_count: int = 1):
        super().__init__(EngineConfig(engine_id=engine_id))
        self.findings_count = findings_count

    async def scan(self, target: str, vectors: list):
        findings = []
        for i in range(self.findings_count):
            f = Finding(
                type=VulnerabilityType.SQL_INJECTION,
                endpoint=vectors[0]["endpoint"],
                parameter=vectors[0]["parameter"],
                payload=vectors[0].get("payloads", [""])[0],
                confidence=0.7,
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


def test_engine_orchestrator_run_chain_template():
    import backend.engines.base as base
    base._engines.clear()

    e_sql = SimpleEngine("engine_sql", findings_count=1)
    e_payload = SimpleEngine("engine_payload", findings_count=0)

    register_engine("engine_sql", e_sql)
    register_engine("engine_payload", e_payload)

    chain = {
        "name": "integration_chain",
        "base_cvss": 7.0,
        "steps": [
            {"id": "s1", "engine": "engine_sql", "description": "detect"},
            {"id": "s2", "engine": "engine_payload", "description": "probe"},
        ],
    }

    orch = EngineOrchestrator()
    vectors = [{"endpoint": "/", "parameter": "id", "payloads": ["1' OR 1=1"]}]

    result = asyncio.run(orch.run_chain_template(chain, "http://example", vectors))

    assert result["chain"] == "integration_chain"
    assert len(result["steps"]) == 2
    assert result["steps"][0]["ok"] is True
    assert result["steps"][1]["ok"] is False
    assert result["success"] is False
