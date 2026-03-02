"""
WAF Feedback Loop Engine - Adaptive Evasion

Processes WAF response signals (blocks, captchas, rate limits) 
and dynamically adjusts payload mutation and evasion behaviors in real-time.
"""

import logging
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger("cerberus.evasion.feedback")


@dataclass
class ResponseSignal:
    status_code: int
    headers: Dict[str, str]
    elapsed_ms: int
    body_snippet: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_block(self) -> bool:
        return self.status_code in (403, 406, 501)

    @property
    def is_rate_limit(self) -> bool:
        return self.status_code == 429

    @property
    def has_captcha(self) -> bool:
        body = self.body_snippet.lower()
        return "captcha" in body or "challenge" in body or "cf-browser-verification" in body


class WAFResponseAnalyzer:
    """Analyzes recent HTTP responses to infer WAF behavior."""
    
    def __init__(self, window_size: int = 20):
        self.window_size = window_size
        self.history: List[ResponseSignal] = []

    def record_response(self, status_code: int, headers: Dict[str, str], body_snippet: str, elapsed_ms: int):
        signal = ResponseSignal(
            status_code=status_code,
            headers={k.lower(): v for k, v in headers.items()},
            elapsed_ms=elapsed_ms,
            body_snippet=body_snippet[:500]
        )
        self.history.append(signal)
        if len(self.history) > self.window_size:
            self.history.pop(0)
        return signal

    def record_interaction(self, status_code: int, latency_ms: int, headers: Dict[str, str] = None, body: str = "", is_blocked: bool = False):
        """Alias for record_response with signature used by the orchestrator."""
        return self.record_response(
            status_code=status_code,
            headers=headers or {},
            body_snippet=body or ("WAF Block" if is_blocked else ""),
            elapsed_ms=latency_ms
        )

    def get_block_rate(self) -> float:
        """Calculate the percentage of recent requests that were blocked."""
        if not self.history:
            return 0.0
        blocks = sum(1 for s in self.history if s.is_block)
        return blocks / len(self.history)

    def detect_rate_limiting(self) -> bool:
        """Check if we are hitting rate limits."""
        return any(s.is_rate_limit for s in self.history[-5:])

    def detect_captcha(self) -> bool:
        """Check if a captcha challenge was presented recently."""
        return any(s.has_captcha for s in self.history[-3:])

    def get_average_latency(self) -> int:
        if not self.history:
            return 0
        return sum(s.elapsed_ms for s in self.history) // len(self.history)


class AdaptiveStrategySelector:
    """Dynamically chooses evasion strategies based on analyzer feedback."""
    
    def __init__(self, analyzer: WAFResponseAnalyzer):
        self.analyzer = analyzer
        self.current_aggressiveness = 1  # 1 to 3
        self.browser_stealth_active = False
        self.jitter_multiplier = 1.0

    def get_next_evasion_context(self) -> Dict[str, Any]:
        """Provides the recommended context/settings for the next request."""
        block_rate = self.analyzer.get_block_rate()
        
        # Adjust aggressiveness based on blocks
        if block_rate > 0.3:
            self.current_aggressiveness = min(3, self.current_aggressiveness + 1)
        elif block_rate == 0.0 and len(self.analyzer.history) >= 10:
            self.current_aggressiveness = max(1, self.current_aggressiveness - 1)

        # React to Captchas
        if self.analyzer.detect_captcha():
            self.browser_stealth_active = True
            logger.info("Captcha detected. Enabling Browser Stealth bypass mode.")

        # React to Rate limits
        if self.analyzer.detect_rate_limiting():
            self.jitter_multiplier = min(3.0, self.jitter_multiplier * 1.5)
            logger.info(f"Rate limit hit. Increasing jitter multiplier to {self.jitter_multiplier}")
        elif block_rate == 0.0 and self.jitter_multiplier > 1.0:
            self.jitter_multiplier = max(1.0, self.jitter_multiplier - 0.1)

        return {
            "aggressiveness": self.current_aggressiveness,
            "use_browser_stealth": self.browser_stealth_active,
            "jitter_multiplier": self.jitter_multiplier,
            "block_rate": block_rate,
            "recommended_technique": self._select_technique(block_rate)
        }

    def _select_technique(self, block_rate: float) -> str:
        if block_rate > 0.5:
            return "base64_json_encap" if random.random() > 0.5 else "header_injection"
        elif block_rate > 0.2:
            return "unicode_homoglyphs"
        return "standard"
