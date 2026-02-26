"""
Cerberus Pro - Report Encryption Module
AES-256-GCM encryption for scan reports and extracted data.
Compliance: GDPR/SOC2 data-at-rest protection.
"""

import json
import logging
import os
from typing import Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("cerberus.encryption")

_NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM
_KEY_SIZE = 32    # 256-bit key
_TAG_SIZE = 16    # 128-bit tag (appended by AESGCM automatically)


def get_encryption_key() -> bytes:
    """
    Load encryption key from ENCRYPTION_KEY env var (hex-encoded, 64 chars).
    If not set, generates an ephemeral key and warns (dev mode only).
    """
    raw = os.environ.get("ENCRYPTION_KEY", "").strip()
    if raw:
        try:
            key = bytes.fromhex(raw)
            if len(key) != _KEY_SIZE:
                raise ValueError(f"ENCRYPTION_KEY must be {_KEY_SIZE} bytes ({_KEY_SIZE * 2} hex chars), got {len(key)}")
            return key
        except ValueError as e:
            raise ValueError(f"Invalid ENCRYPTION_KEY: {e}") from e

    # Dev fallback: generate ephemeral key
    key = os.urandom(_KEY_SIZE)
    logger.warning(
        "⚠️  ENCRYPTION_KEY not set — using ephemeral key. "
        "Reports encrypted in this session CANNOT be decrypted after restart. "
        "Set ENCRYPTION_KEY env var for production use."
    )
    return key


def encrypt_report(data: dict, key: bytes) -> bytes:
    """
    Encrypt a report dict with AES-256-GCM.

    Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)

    Args:
        data: Report dict to encrypt (will be JSON-serialized)
        key: 32-byte encryption key
    """
    if len(key) != _KEY_SIZE:
        raise ValueError(f"Key must be {_KEY_SIZE} bytes, got {len(key)}")

    plaintext = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag concatenated
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    return nonce + ciphertext_with_tag


def decrypt_report(encrypted: bytes, key: bytes) -> dict:
    """
    Decrypt an AES-256-GCM encrypted report.

    Args:
        encrypted: nonce (12 bytes) + ciphertext + tag (16 bytes)
        key: 32-byte encryption key

    Returns:
        Decrypted report dict

    Raises:
        ValueError: If authentication tag is invalid (data tampered)
        ValueError: If encrypted data is too short
    """
    if len(key) != _KEY_SIZE:
        raise ValueError(f"Key must be {_KEY_SIZE} bytes, got {len(key)}")
    if len(encrypted) < _NONCE_SIZE + _TAG_SIZE + 1:
        raise ValueError("Encrypted data is too short to contain valid ciphertext")

    nonce = encrypted[:_NONCE_SIZE]
    ciphertext_with_tag = encrypted[_NONCE_SIZE:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception as e:
        raise ValueError(f"Decryption failed — data may be tampered or wrong key: {e}") from e

    return json.loads(plaintext.decode("utf-8"))
