"""Tests for Intelligent AutoPilot defensive measure detection."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from autopilot_utils import detect_defensive_measures


class TestWAFDetection:
    """Verify WAF signature detection in scan output."""

    def test_detect_cloudflare(self):
        logs = """
[14:30:01] [WARNING] heuristic (basic) test shows that GET parameter 'id' might be injectable
[14:30:02] [WARNING] 403 Forbidden with Cloudflare challenge page
[14:30:03] [INFO] testing for SQL injection on GET parameter 'id'
        """
        result = detect_defensive_measures(logs)
        assert result["waf_detected"] is True
        assert any("cloudflare" in sig.lower() for sig in result.get("signatures", []))

    def test_detect_modsecurity(self):
        logs = """
[14:30:01] [WARNING] ModSecurity rules detected
[14:30:02] [WARNING] heuristic (basic) test shows that POST parameter 'user' is not injectable
        """
        result = detect_defensive_measures(logs)
        assert result["waf_detected"] is True

    def test_detect_generic_waf(self):
        logs = """
[14:30:01] [WARNING] WAF/IPS/IDS identified
[14:30:02] [CRITICAL] potential WAF/IPS detected (connection reset)
        """
        result = detect_defensive_measures(logs)
        assert result["waf_detected"] is True


class TestRateLimiting:
    """Verify rate limiting detection."""

    def test_detect_429_responses(self):
        logs = """
[14:30:01] [WARNING] HTTP error code 429 (Too Many Requests)
[14:30:02] [WARNING] HTTP error code 429 (Too Many Requests)
[14:30:03] [WARNING] HTTP error code 429 (Too Many Requests)
        """
        result = detect_defensive_measures(logs)
        assert result["rate_limited"] is True
        assert result["rate_limit_count"] >= 3

    def test_detect_503_as_rate_limit(self):
        logs = """
[14:30:01] [WARNING] HTTP error code 503 (Service Unavailable)
[14:30:02] [WARNING] HTTP error code 503 (Service Unavailable)
        """
        result = detect_defensive_measures(logs)
        # 503 can indicate rate limiting
        assert result["rate_limited"] is True or result["connection_issues"]

    def test_detect_repeated_403_as_waf_signal(self):
        logs = """
[14:30:01] [WARNING] HTTP error code 403 (Forbidden)
[14:30:02] [WARNING] access denied by upstream filter
[14:30:03] [WARNING] HTTP error code 403 (Forbidden)
        """
        result = detect_defensive_measures(logs)
        assert result["waf_detected"] is True
        assert any("403" in sig for sig in result.get("signatures", []))

    def test_detect_repeated_502_as_connection_instability(self):
        logs = """
[14:30:01] [WARNING] HTTP error code 502 (Bad Gateway)
[14:30:02] [WARNING] HTTP error code 502 (Bad Gateway)
        """
        result = detect_defensive_measures(logs)
        assert result["connection_issues"] is True


class TestHoneypotDetection:
    """Verify honeypot detection via uniform responses."""

    def test_detect_honeypot_uniform(self):
        logs = """
[14:30:01] [WARNING] target returned identical content with different payloads
[14:30:02] [WARNING] target returned identical content with different payloads
[14:30:03] [WARNING] connection appears to be monitored (identical responses)
        """
        result = detect_defensive_measures(logs)
        assert result["honeypot_probability"] > 0.5

    def test_low_honeypot_normal_scan(self):
        logs = """
[14:30:01] [INFO] testing for SQL injection on GET parameter 'id'
[14:30:02] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind'
        """
        result = detect_defensive_measures(logs)
        assert result["honeypot_probability"] < 0.3


class TestRecommendedAction:
    """Verify action recommendations based on detected measures."""

    def test_recommend_abort_on_honeypot(self):
        logs = """
[WARNING] target returned identical content with different payloads
[WARNING] target returned identical content with different payloads
[WARNING] connection appears to be monitored (identical responses)
[WARNING] target returned identical content with different payloads
        """
        result = detect_defensive_measures(logs)
        assert result["recommended_action"] in ("abort", "reduce_aggression")

    def test_recommend_reduce_on_rate_limit(self):
        logs = """
[WARNING] HTTP error code 429 (Too Many Requests)
[WARNING] HTTP error code 429 (Too Many Requests)
        """
        result = detect_defensive_measures(logs)
        assert result["recommended_action"] in ("reduce_aggression", "abort")

    def test_recommend_continue_clean(self):
        logs = """
[INFO] testing for SQL injection on GET parameter 'id'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
        """
        result = detect_defensive_measures(logs)
        assert result["recommended_action"] == "continue"

    def test_recommend_abort_on_waf_plus_rate_limit(self):
        logs = """
[WARNING] WAF/IPS/IDS identified
[WARNING] HTTP error code 429 (Too Many Requests)
[WARNING] HTTP error code 429 (Too Many Requests)
[WARNING] HTTP error code 429 (Too Many Requests)
        """
        result = detect_defensive_measures(logs)
        assert result["recommended_action"] == "abort"
