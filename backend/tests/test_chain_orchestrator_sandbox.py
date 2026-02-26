import os
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.join(os.getcwd(), "backend"))

from backend.core.chain_orchestrator import ChainLink, ChainOrchestrator, VulnerabilityFinding, VulnerabilityType
from backend.core.sandbox_runner import SandboxConfig, SandboxMode, SandboxRunner


class _FakeAdapter:
    name = "fake"

    def supports(self, technique, command_template, vuln_type):
        return True

    def required_dependencies(self):
        return ["fake_dep"]

    def build_command(self, technique, command_template, endpoint, parameter):
        return type(
            "EngineCommandLike",
            (),
            {
                "engine": "fake",
                "command": [sys.executable, "-c", "print('chain-adapter-ok')"],
                "timeout_sec": 5,
                "allow_network": False,
            },
        )()


class _FakeRegistry:
    def find_adapter(self, technique, command_template, vuln_type):
        return _FakeAdapter()


@pytest.mark.asyncio
async def test_execute_link_uses_adapter_and_sandbox():
    orchestrator = ChainOrchestrator()
    orchestrator.adapter_registry = _FakeRegistry()
    orchestrator.sandbox_runner = SandboxRunner(SandboxConfig(mode=SandboxMode.LOCAL, timeout_sec=10))

    link = ChainLink(
        source_vuln=VulnerabilityType.SQL_INJECTION,
        target_vuln=None,
        technique="enum",
        confidence=1.0,
        preconditions=[],
        postconditions=[],
        time_estimate_ms=1000,
        command_template="fake-template",
    )
    finding = VulnerabilityFinding(
        type=VulnerabilityType.SQL_INJECTION,
        endpoint="https://example.org/test?id=1",
        parameter="id",
        confirmed=True,
        confidence=0.99,
        payload="1'",
        response_evidence="evidence",
        discovered_at=datetime.utcnow(),
        severity="high",
    )

    result = await orchestrator._execute_link(link, finding)
    assert result["success"] is True
    assert "chain-adapter-ok" in result["output"]
    assert "sandbox=local" in result["evidence"]

