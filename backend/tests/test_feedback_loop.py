"""
Tests for Phase 2 — Adaptive Evasion subsystem.

Covers:
- WAF feedback loop (WAFResponseAnalyzer, AdaptiveStrategySelector)
- ProxyRotator
- Expanded WAF presets in evasion_strategies.py
"""

import pytest
from datetime import datetime
from backend.core.waf_feedback_loop import WAFResponseAnalyzer, AdaptiveStrategySelector, ResponseSignal
from backend.offensiva.proxy_rotator import ProxyRotator
from backend.offensiva.evasion_strategies import get_bypass_strategies, WAF_STRATEGIES

class TestFeedbackLoop:
    
    def test_analyzer_record_response(self):
        analyzer = WAFResponseAnalyzer(window_size=5)
        for i in range(10):
            analyzer.record_response(200, {"Server": "nginx"}, "ok", 50)
        assert len(analyzer.history) == 5  # Window size limits history
        assert analyzer.get_block_rate() == 0.0

    def test_analyzer_detect_blocks(self):
        analyzer = WAFResponseAnalyzer()
        analyzer.record_response(403, {}, "Forbidden", 10)
        analyzer.record_response(406, {}, "Not Acceptable", 10)
        analyzer.record_response(200, {}, "ok", 50)
        assert analyzer.get_block_rate() == 2/3

    def test_analyzer_detect_captcha(self):
        analyzer = WAFResponseAnalyzer()
        analyzer.record_response(200, {}, "cf-browser-verification", 100)
        assert analyzer.detect_captcha() is True

    def test_analyzer_detect_rate_limit(self):
        analyzer = WAFResponseAnalyzer()
        analyzer.record_response(429, {}, "Too many requests", 10)
        assert analyzer.detect_rate_limiting() is True

    def test_strategy_selector_escalation(self):
        analyzer = WAFResponseAnalyzer()
        selector = AdaptiveStrategySelector(analyzer)
        
        # Initial state
        ctx = selector.get_next_evasion_context()
        assert ctx["aggressiveness"] == 1
        assert ctx["use_browser_stealth"] is False
        
        # Simulate blocks
        analyzer.record_response(403, {}, "Blocked", 10)
        analyzer.record_response(403, {}, "Blocked", 10)
        
        ctx = selector.get_next_evasion_context()
        assert ctx["aggressiveness"] == 2  # Escalated
        
        # Simulate captcha
        analyzer.record_response(403, {}, "Please complete captcha", 10)
        ctx = selector.get_next_evasion_context()
        assert ctx["use_browser_stealth"] is True

    def test_strategy_selector_jitter_increase(self):
        analyzer = WAFResponseAnalyzer()
        selector = AdaptiveStrategySelector(analyzer)
        
        analyzer.record_response(429, {}, "Rate limited", 10)
        ctx = selector.get_next_evasion_context()
        assert ctx["jitter_multiplier"] == 1.5

class TestProxyRotator:
    
    def test_add_and_get_proxy(self):
        rotator = ProxyRotator()
        rotator.add_proxy("http://1.1.1.1:8080")
        rotator.add_proxy("socks5://2.2.2.2:1080")
        
        assert rotator.get_next() == "http://1.1.1.1:8080"
        assert rotator.get_next() == "socks5://2.2.2.2:1080"
        # Round robin
        assert rotator.get_next() == "http://1.1.1.1:8080"

    def test_burn_proxy(self):
        rotator = ProxyRotator(["http://p1", "http://p2"])
        assert rotator.get_next() == "http://p1"
        rotator.mark_burned("http://p2")
        # Should skip p2
        assert rotator.get_next() == "http://p1"

    def test_get_sqlmap_args(self):
        rotator = ProxyRotator(["http://p1", "http://p2"])
        args = rotator.get_sqlmap_args()
        assert "--proxy=http://p1,http://p2" in args
        assert "--random-agent" in args

class TestEvasionStrategies:
    
    def test_waf_presets_expanded(self):
        # We should have 12 WAF presets now
        assert len(WAF_STRATEGIES) == 12
        
        # Verify new ones are present
        assert "Sucuri" in WAF_STRATEGIES
        assert "Wordfence" in WAF_STRATEGIES
        assert "AWS_WAF" in WAF_STRATEGIES
        assert "Citrix_ADC" in WAF_STRATEGIES

    def test_get_bypass_strategies(self):
        strats = get_bypass_strategies("Sucuri")
        assert "use_hex_encoding" in strats
        assert "comment_injection" in strats
        
        # Unknown falls back to generic
        generic = get_bypass_strategies("UnknownWAF")
        assert generic == WAF_STRATEGIES["GenericWAF"]
