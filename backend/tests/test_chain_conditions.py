import asyncio

from backend.core.chain_orchestrator_v2 import ChainOrchestratorV2
from backend.engines.base import EngineAdapter, EngineConfig, Finding, VulnerabilityType, Severity, register_engine


class ReturnEngine(EngineAdapter):
    def __init__(self, engine_id: str, findings_count: int):
        super().__init__(EngineConfig(engine_id=engine_id))
        self.findings_count = findings_count

    async def scan(self, target: str, vectors: list):
        results = []
        for i in range(self.findings_count):
            results.append(Finding(
                type=VulnerabilityType.SQL_INJECTION,
                endpoint=vectors[0]["endpoint"],
                parameter=vectors[0]["parameter"],
                payload=vectors[0].get("payloads", [""])[0],
                confidence=0.5,
                severity=Severity.LOW,
                evidence="synthetic",
                engine=self.config.engine_id,
            ))
        return results

    def get_status(self):
        return {"engine": self.config.engine_id}

    async def stop(self):
        return


def test_required_findings_and_continue_flag():
    import backend.engines.base as base
    base._engines.clear()

    # Engine A returns 2 findings, Engine B returns 0
    a = ReturnEngine("eng_a", 2)
    b = ReturnEngine("eng_b", 0)
    register_engine("eng_a", a)
    register_engine("eng_b", b)

    chain = {
        "name": "cond_chain",
        "steps": [
            {"id": "step1", "engine": "eng_a", "required_findings": 2},
            {"id": "step2", "engine": "eng_b", "required_findings": 1, "continue_on_failure": True},
            {"id": "step3", "engine": "eng_b", "required_findings": 1, "continue_on_failure": False},
        ],
    }

    orch = ChainOrchestratorV2()
    vectors = [{"endpoint": "/", "parameter": "id", "payloads": ["p"]}]

    result = asyncio.run(orch.run_chain_async(chain, "http://t", vectors))

    # step1 should pass (2 findings >=2)
    assert result["steps"][0]["ok"] is True
    # step2 should fail but continue_on_failure True: ok False, overall still pending
    assert result["steps"][1]["ok"] is False
    # step3 should fail and cause overall failure
    assert result["steps"][2]["ok"] is False
    assert result["success"] is False
