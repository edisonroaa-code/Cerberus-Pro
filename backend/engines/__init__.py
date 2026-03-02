"""
Cerberus Pro v4 - Engine Module

Auto-registers all vulnerability scanning engines.
Provides unified interface for multi-engine orchestration.
"""

import logging

from .base import (
    Finding,
    VulnerabilityType,
    Severity,
    EngineAdapter,
    EngineConfig,
    register_engine,
    get_engine,
    list_engines,
    is_engine_registered,
)
from .sqlmap_adapter import SqlmapAdapter
from .zap_adapter import ZapAdapter
from .burp_adapter import BurpAdapter
from .nmap_adapter import NmapAdapter
from .custom_payload_adapter import CustomPayloadAdapter
from .advanced_payload_adapter import AdvancedPayloadAdapter
from .orchestrator import EngineOrchestrator

logger = logging.getLogger("cerberus.engines")


def register_default_engines():
    """Register all built-in engines with default configurations"""
    
    # SQLmap adapter for SQL injection testing
    register_engine(
        "sqlmap",
        SqlmapAdapter(
            config=EngineConfig(
                engine_id="sqlmap",
                timeout_ms=180000,  # 3 minutes - needed for level=5 + risk=3
                max_payloads=100,
                rate_limit_rps=10,
            )
        ),
    )
    logger.info("Registered engine: sqlmap")

    # OWASP ZAP adapter for multi-vulnerability detection
    register_engine(
        "zap",
        ZapAdapter(
            config=EngineConfig(
                engine_id="zap",
                timeout_ms=60000,
                max_payloads=50,
                rate_limit_rps=5,
                custom_params={"zap_url": "http://localhost:8080", "api_key": ""},
            )
        ),
    )
    logger.info("Registered engine: zap")

    # Burp adapter (proxy-aware active adapter)
    register_engine(
        "burp",
        BurpAdapter(
            config=EngineConfig(
                engine_id="burp",
                timeout_ms=60000,
                max_payloads=50,
                rate_limit_rps=5,
                custom_params={"burp_url": "http://127.0.0.1:1337"},
            )
        ),
    )
    logger.info("Registered engine: burp")

    # Nmap adapter for network reconnaissance
    register_engine(
        "nmap",
        NmapAdapter(
            config=EngineConfig(
                engine_id="nmap",
                timeout_ms=45000,
                max_payloads=1,  # Nmap doesn't use payloads
                rate_limit_rps=1,
            )
        ),
    )
    logger.info("Registered engine: nmap")

    # Custom payload adapter for fast parallel testing
    register_engine(
        "custom_payload",
        CustomPayloadAdapter(
            config=EngineConfig(
                engine_id="custom_payload",
                timeout_ms=20000,
                max_payloads=50,
                rate_limit_rps=20,
            )
        ),
    )
    logger.info("Registered engine: custom_payload")

    # Advanced payload adapter (Payload Mutation v2)
    register_engine(
        "advanced_payload",
        AdvancedPayloadAdapter(
            config=EngineConfig(
                engine_id="advanced_payload",
                timeout_ms=30000,
                max_payloads=200,
                rate_limit_rps=40,
                custom_params={"mutation_level": 2},
            )
        ),
    )
    logger.info("Registered engine: advanced_payload")


# Auto-register on module import
try:
    register_default_engines()
    logger.info(f"Engine subsystem initialized: {len(list_engines())} engines available")
except Exception as e:
    logger.error(f"Failed to initialize engines: {e}")

__all__ = [
    "Finding",
    "VulnerabilityType",
    "Severity",
    "EngineAdapter",
    "EngineConfig",
    "EngineOrchestrator",
    "register_engine",
    "get_engine",
    "list_engines",
    "is_engine_registered",
    "SqlmapAdapter",
    "ZapAdapter",
    "BurpAdapter",
    "NmapAdapter",
    "CustomPayloadAdapter",
    "AdvancedPayloadAdapter",
]
