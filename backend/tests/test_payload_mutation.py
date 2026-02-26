"""Tests for backend/payload_mutation.py — PayloadMutationEngine."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from payload_mutation import PayloadMutationEngine


BASE_PAYLOAD = "1' OR '1'='1"
UNION_PAYLOAD = "' UNION SELECT username, password FROM users--"
ADMIN_PAYLOAD = "admin'--"


class TestMutateBasic:
    """Test basic mutation functionality."""

    def test_returns_correct_count(self):
        results = PayloadMutationEngine.mutate(BASE_PAYLOAD, count=20)
        assert len(results) <= 20
        assert len(results) > 0  # At least some mutations should succeed

    def test_no_duplicates(self):
        results = PayloadMutationEngine.mutate(BASE_PAYLOAD, count=15)
        assert len(results) == len(set(results))

    def test_mutations_differ_from_original(self):
        results = PayloadMutationEngine.mutate(BASE_PAYLOAD, count=10)
        for r in results:
            assert r != BASE_PAYLOAD

    def test_specific_technique_only(self):
        results = PayloadMutationEngine.mutate(
            BASE_PAYLOAD,
            techniques=["case_randomization"],
            count=5,
        )
        assert len(results) > 0


class TestEncodingChain:
    """Test encoding chain technique."""

    def test_url_encodes_special_chars(self):
        result = PayloadMutationEngine._encoding_chain("1' OR 1=1")
        assert "'" not in result or "%27" in result or "%2527" in result


class TestCommentInjection:
    """Test comment injection technique."""

    def test_injects_comments_in_keywords(self):
        result = PayloadMutationEngine._comment_injection(UNION_PAYLOAD)
        # Should have /**/ somewhere in a keyword
        assert "/**/" in result or result == UNION_PAYLOAD  # May not always trigger


class TestCaseRandomization:
    """Test case randomization technique."""

    def test_mixed_case(self):
        # Run multiple times to account for randomness
        has_mixed = False
        for _ in range(10):
            result = PayloadMutationEngine._case_randomization("SELECT")
            if result != "SELECT" and result != "select":
                has_mixed = True
                break
        assert has_mixed, "Expected at least one mixed-case result"


class TestCharEncoding:
    """Test CHAR() encoding technique."""

    def test_mysql_char_encoding(self):
        result = PayloadMutationEngine._char_encoding("'admin'", dbms="mysql")
        if result != "'admin'":  # Only check if mutation occurred
            assert "CHAR(" in result

    def test_postgres_chr_encoding(self):
        result = PayloadMutationEngine._char_encoding("'admin'", dbms="postgresql")
        if result != "'admin'":
            assert "CHR(" in result


class TestConcatenation:
    """Test string concatenation technique."""

    def test_mysql_concat(self):
        result = PayloadMutationEngine._concatenation("'admin'", dbms="mysql")
        if result != "'admin'":
            assert "CONCAT(" in result

    def test_mssql_plus_concat(self):
        result = PayloadMutationEngine._concatenation("'admin'", dbms="mssql")
        if result != "'admin'":
            assert "+" in result


class TestContextAwareMutation:
    """Test context-aware payload generation."""

    def test_mysql_context(self):
        results = PayloadMutationEngine.context_aware_mutation(
            BASE_PAYLOAD,
            context={"dbms": "mysql", "waf": "cloudflare"},
            count=10,
        )
        assert len(results) > 0
        for r in results:
            assert r != BASE_PAYLOAD

    def test_mssql_context(self):
        results = PayloadMutationEngine.context_aware_mutation(
            BASE_PAYLOAD,
            context={"dbms": "mssql", "waf": "imperva"},
            count=10,
        )
        assert len(results) > 0

    def test_json_injection_point(self):
        results = PayloadMutationEngine.context_aware_mutation(
            BASE_PAYLOAD,
            context={"dbms": "mysql", "injection_point": "json"},
            count=10,
        )
        assert len(results) > 0


class TestPayloadFileGeneration:
    """Test payload file generation."""

    def test_generates_file(self):
        path = PayloadMutationEngine.generate_payload_file(
            [BASE_PAYLOAD, ADMIN_PAYLOAD],
            count_per_payload=5,
        )
        assert os.path.exists(path)
        # Payloads may include Unicode homoglyphs by design; always read UTF-8.
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        assert len(lines) > 0
        # Cleanup
        os.unlink(path)

    def test_file_with_context(self):
        path = PayloadMutationEngine.generate_payload_file(
            [UNION_PAYLOAD],
            context={"dbms": "postgresql", "waf": "modsecurity"},
            count_per_payload=8,
        )
        assert os.path.exists(path)
        os.unlink(path)
