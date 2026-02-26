"""Tests for backend/encryption.py — AES-256-GCM report encryption."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from encryption import encrypt_report, decrypt_report, get_encryption_key


class TestEncryptDecryptRoundtrip:
    """Verify data survives encrypt → decrypt cycle."""

    def test_roundtrip_simple(self):
        key = os.urandom(32)
        data = {"vulnerable": True, "data": ["admin", "root"], "count": 2}
        encrypted = encrypt_report(data, key)
        decrypted = decrypt_report(encrypted, key)
        assert decrypted == data

    def test_roundtrip_unicode(self):
        key = os.urandom(32)
        data = {"target": "https://ejemplo.com/búsqueda?q=café", "nota": "ñandú"}
        encrypted = encrypt_report(data, key)
        decrypted = decrypt_report(encrypted, key)
        assert decrypted == data

    def test_roundtrip_large_data(self):
        key = os.urandom(32)
        data = {"rows": [{"id": i, "name": f"user_{i}"} for i in range(1000)]}
        encrypted = encrypt_report(data, key)
        decrypted = decrypt_report(encrypted, key)
        assert len(decrypted["rows"]) == 1000

    def test_roundtrip_empty_dict(self):
        key = os.urandom(32)
        data = {}
        encrypted = encrypt_report(data, key)
        decrypted = decrypt_report(encrypted, key)
        assert decrypted == data


class TestTamperDetection:
    """Verify tampered ciphertext is rejected."""

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        data = {"secret": "password123"}
        encrypted = bytearray(encrypt_report(data, key))
        # Flip a byte in the middle of the ciphertext
        mid = len(encrypted) // 2
        encrypted[mid] ^= 0xFF
        with pytest.raises(ValueError, match="tampered|wrong key"):
            decrypt_report(bytes(encrypted), key)

    def test_truncated_data_raises(self):
        key = os.urandom(32)
        data = {"test": True}
        encrypted = encrypt_report(data, key)
        with pytest.raises(ValueError, match="too short"):
            decrypt_report(encrypted[:10], key)


class TestKeyManagement:
    """Verify key retrieval and generation."""

    def test_different_keys_fail(self):
        key_a = os.urandom(32)
        key_b = os.urandom(32)
        data = {"confidential": True}
        encrypted = encrypt_report(data, key_a)
        with pytest.raises(ValueError):
            decrypt_report(encrypted, key_b)

    def test_wrong_key_size_encrypt(self):
        with pytest.raises(ValueError, match="must be 32"):
            encrypt_report({"x": 1}, b"short_key")

    def test_wrong_key_size_decrypt(self):
        with pytest.raises(ValueError, match="must be 32"):
            decrypt_report(b"\x00" * 50, b"short_key")

    def test_get_encryption_key_from_env(self, monkeypatch):
        test_key = os.urandom(32)
        monkeypatch.setenv("ENCRYPTION_KEY", test_key.hex())
        key = get_encryption_key()
        assert key == test_key

    def test_get_encryption_key_generates_warning(self, monkeypatch, caplog):
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        import logging
        with caplog.at_level(logging.WARNING, logger="cerberus.encryption"):
            key = get_encryption_key()
        assert len(key) == 32
        assert "ephemeral" in caplog.text.lower() or "ENCRYPTION_KEY" in caplog.text

    def test_invalid_hex_key_raises(self, monkeypatch):
        monkeypatch.setenv("ENCRYPTION_KEY", "not_valid_hex")
        with pytest.raises(ValueError, match="Invalid ENCRYPTION_KEY"):
            get_encryption_key()
