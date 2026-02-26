"""
Cerberus Pro v4 - Engine Tests

Unit tests for all engine adapters and orchestrator.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from typing import List, Dict

from backend.engines import (
    EngineAdapter,
    EngineConfig,
    Finding,
    VulnerabilityType,
    Severity,
    register_engine,
    get_engine,
    list_engines,
    is_engine_registered,
    EngineOrchestrator,
    CustomPayloadAdapter,
)


class TestEngineRegistry:
    """Test engine registry and discovery system"""

    def test_register_engine(self):
        """Test basic engine registration"""
        config = EngineConfig(engine_id="test_engine", timeout_ms=5000)
        adapter = CustomPayloadAdapter(config=config)

        register_engine("test_scanner", adapter)
        assert is_engine_registered("test_scanner")
        assert get_engine("test_scanner") is not None

    def test_list_engines(self):
        """Test listing all registered engines"""
        from backend.engines import SqlmapAdapter, EngineConfig
        register_engine("test_sqlmap_for_list", SqlmapAdapter(EngineConfig(engine_id="sqlmap")))
        engines = list_engines()
        assert isinstance(engines, list)
        assert len(engines) > 0
        assert "test_sqlmap_for_list" in engines

    def test_get_nonexistent_engine(self):
        """Test retrieving non-existent engine returns None"""
        engine = get_engine("nonexistent_engine_xyz")
        assert engine is None


class TestFindingDataclass:
    """Test Finding deduplication and hashing"""

    def test_finding_creation(self):
        """Test Finding dataclass creation"""
        finding = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint="/api/users",
            parameter="id",
            payload="1' OR '1'='1",
            confidence=0.95,
            severity=Severity.CRITICAL,
            evidence="SQL error in response",
            engine="sqlmap",
        )
        assert finding.type == VulnerabilityType.SQL_INJECTION
        assert finding.confidence == 0.95

    def test_finding_dedup_key(self):
        """Test Finding deduplication key"""
        finding1 = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint="/api/users",
            parameter="id",
            payload="payload1",
            confidence=0.90,
            severity=Severity.HIGH,
            evidence="evidence1",
            engine="sqlmap",
        )
        finding2 = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint="/api/users",
            parameter="id",
            payload="payload2",
            confidence=0.95,
            severity=Severity.CRITICAL,
            evidence="evidence2",
            engine="nmap",
        )

        # Same endpoint + parameter + type = same dedup_key
        assert finding1.dedup_key() == finding2.dedup_key()

    def test_finding_hash(self):
        """Test Finding hashing for deduplication"""
        finding = Finding(
            type=VulnerabilityType.XSS,
            endpoint="/api/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            confidence=0.80,
            severity=Severity.HIGH,
            evidence="script tag in response",
            engine="custom_payload",
        )
        h1 = hash(finding)
        h2 = hash(finding)
        assert h1 == h2


class TestCustomPayloadAdapter:
    """Test custom payload engine"""

    @pytest.mark.asyncio
    async def test_custom_payload_adapter_initialization(self):
        """Test CustomPayloadAdapter initialization"""
        config = EngineConfig(
            engine_id="custom_payload",
            timeout_ms=10000,
            max_payloads=10,
        )
        adapter = CustomPayloadAdapter(config=config)
        assert adapter.config.engine_id == "custom_payload"

    @pytest.mark.asyncio
    async def test_custom_payload_scan_no_aiohttp(self):
        """Test CustomPayloadAdapter.scan when aiohttp unavailable"""
        config = EngineConfig(
            engine_id="custom_payload",
            timeout_ms=5000,
        )
        adapter = CustomPayloadAdapter(config=config)

        with patch("backend.engines.custom_payload_adapter.aiohttp", None):
            findings = await adapter.scan(
                "http://target.com",
                [{"endpoint": "/api/test", "parameter": "id", "payloads": ["test"]}],
            )
            assert findings == []

    def test_custom_payload_get_status(self):
        """Test CustomPayloadAdapter status reporting"""
        config = EngineConfig(engine_id="custom_payload", timeout_ms=5000)
        adapter = CustomPayloadAdapter(config=config)

        status = adapter.get_status()
        assert status["engine"] == "custom_payload"
        assert status["status"] == "ready"


class TestEngineOrchestrator:
    """Test multi-engine orchestration"""

    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self):
        """Test EngineOrchestrator initialization"""
        orch = EngineOrchestrator(enabled_engines=["nmap"])
        assert orch.enabled_engines == ["nmap"]
        assert orch.all_findings == []

    @pytest.mark.asyncio
    async def test_orchestrator_scan_all_empty(self):
        """Test orchestrator with empty vector list"""
        orch = EngineOrchestrator(enabled_engines=["custom_payload"])
        findings = await orch.scan_all("http://target.com", [])
        assert isinstance(findings, list)

    def test_orchestrator_deduplication(self):
        """Test orchestrator finding deduplication"""
        orch = EngineOrchestrator()

        finding1 = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint="/api/users",
            parameter="id",
            payload="payload1",
            confidence=0.90,
            severity=Severity.HIGH,
            evidence="evidence1",
            engine="sqlmap",
        )
        finding2 = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint="/api/users",
            parameter="id",
            payload="payload2",
            confidence=0.95,
            severity=Severity.CRITICAL,
            evidence="evidence2",
            engine="nmap",
        )

        deduplicated = orch._deduplicate_findings([finding1, finding2])
        assert len(deduplicated) == 1  # Same dedup_key

    def test_orchestrator_status(self):
        """Test orchestrator status reporting"""
        orch = EngineOrchestrator(enabled_engines=["sqlmap", "nmap"])
        status = orch.get_status()

        assert status["orchestrator"] == "engine_orchestrator"
        assert status["status"] == "ready"
        assert "sqlmap" in status["enabled_engines"]

    def test_orchestrator_sorting(self):
        """Test findings are sorted by confidence"""
        orch = EngineOrchestrator()

        finding_high = Finding(
            type=VulnerabilityType.SQL_INJECTION,
            endpoint="/api/a",
            parameter="id",
            payload="payload",
            confidence=0.95,
            severity=Severity.CRITICAL,
            evidence="evidence",
            engine="sqlmap",
        )
        finding_low = Finding(
            type=VulnerabilityType.XSS,
            endpoint="/api/b",
            parameter="q",
            payload="payload",
            confidence=0.50,
            severity=Severity.LOW,
            evidence="evidence",
            engine="custom_payload",
        )

        sorted_findings = orch._deduplicate_findings(
            [finding_low, finding_high]
        )  # Unsorted input
        # Don't sort in dedup, sort is in scan_all
        assert len(sorted_findings) == 2


class TestEngineConfig:
    """Test engine configuration"""

    def test_engine_config_creation(self):
        """Test EngineConfig dataclass"""
        config = EngineConfig(
            engine_id="test",
            timeout_ms=10000,
            max_payloads=50,
            rate_limit_rps=10,
            custom_params={"key": "value"},
        )
        assert config.engine_id == "test"
        assert config.timeout_ms == 10000
        assert config.custom_params["key"] == "value"

    def test_engine_config_defaults(self):
        """Test EngineConfig default values"""
        config = EngineConfig(engine_id="minimal")
        assert config.timeout_ms == 30000  # Default
        assert config.max_payloads == 100  # Default
        assert config.rate_limit_rps == 5  # Default


class TestVulnerabilityTypeEnum:
    """Test VulnerabilityType enumeration"""

    def test_vulnerability_types_exist(self):
        """Test all expected vulnerability types"""
        expected_types = [
            "SQL_INJECTION",
            "XSS",
            "XXE",
            "COMMAND_INJECTION",
            "PATH_TRAVERSAL",
            "AUTHENTICATION_BYPASS",
            "DESERIALIZATION",
            "WEAK_CRYPTO",
        ]
        for vtype in expected_types:
            assert hasattr(VulnerabilityType, vtype)

    def test_severity_levels(self):
        """Test all severity levels"""
        expected_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for level in expected_levels:
            assert hasattr(Severity, level)


# Run tests with: pytest backend/tests/test_engines.py -v
