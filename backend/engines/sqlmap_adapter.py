"""
Cerberus Pro v4/v5 - Native Engine Adapter
(Mantiene el nombre sqlmap_adapter.py por compatibilidad con el registry)

Ejecuta vectores asíncronos nativos (Boolean, Time) enviando tráfico usando
CerberusHTTPClient sin usar subprocesos externos.
"""

import asyncio
import logging
import os
from typing import List, Dict
from datetime import datetime, timezone
from backend.engines.base import EngineAdapter, Finding, EngineConfig, VulnerabilityType, Severity

from backend.core.cerberus_http_client import CerberusHTTPClient
from backend.core.vector_boolean import VectorBoolean
from backend.core.vector_time import VectorTime

logger = logging.getLogger("cerberus.engines.native")


class SqlmapAdapter(EngineAdapter):
    """
    Antiguo Wrapper de SQLMap, AHORA reemplazado por
    Cerberus Native Engine v5.0 (Asíncrono, AI-first)
    Mantiene el nombre de clase por compatibilidad con el engine registry.
    """

    def __init__(self, config: EngineConfig):
        super().__init__(config)

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        findings = []
        self.start_time = datetime.now(timezone.utc)

        if not vectors:
            logger.warning("No se proporcionaron vectores de ataque al motor Nativo")
            self.end_time = datetime.now(timezone.utc)
            return findings

        # Setup Native Client (Ghost Network Capable)
        # Assuming config.timeout_ms is passed
        timeout_sec = int(self.config.timeout_ms / 1000) if getattr(self.config, 'timeout_ms', 0) else 10
        use_tor = getattr(self.config, 'use_tor', False)
        proxy = getattr(self.config, 'proxy', None)
        
        # Override to use environment variables for Ghost Network if not present in config
        if not use_tor and os.environ.get("CERBERUS_USE_TOR") == "true":
            use_tor = True
            
        async with CerberusHTTPClient(use_tor=use_tor, proxy=proxy, timeout=timeout_sec) as http_client:
            for idx, vector in enumerate(vectors):
                if not self.config.enabled:
                    break

                endpoint = vector.get("endpoint", "/")
                parameter = vector.get("parameter", "id")
                method = vector.get("method", "GET")

                url = f"{target}{endpoint}"
                if method == "GET" and parameter:
                    url += f"?{parameter}=1"
                
                logger.info(f"[{endpoint}] Cerberus Native Engine: Auditando parámetro '{parameter}' de forma asíncrona...")
                
                # 1. Boolean Vector (Differential Match)
                bool_vector = VectorBoolean(http_client, url)
                res_bool = await bool_vector.run({})
                if res_bool.get("status") == "vulnerable":
                    findings.append(Finding(
                        type=VulnerabilityType.SQL_INJECTION,
                        endpoint=endpoint,
                        parameter=parameter,
                        payload="Boolean-based blind differential match",
                        confidence=0.95,
                        severity=Severity.CRITICAL,
                        evidence=res_bool.get("evidence", ""),
                        engine="cerberus_native",
                    ))
                    logger.info(f"✓ [SQLi NATIVO CRITICO] Descubierto por Vector Booleano en: {url}")
                    continue # Stop testing other vectors on this param if vulnerable
                
                # 2. Time Vector (Statistical Latency Match)
                time_vector = VectorTime(http_client, url)
                res_time = await time_vector.run({})
                if res_time.get("status") == "vulnerable":
                    findings.append(Finding(
                        type=VulnerabilityType.SQL_INJECTION,
                        endpoint=endpoint,
                        parameter=parameter,
                        payload="Time-based blind latency match",
                        confidence=0.90,
                        severity=Severity.CRITICAL,
                        evidence=res_time.get("evidence", ""),
                        engine="cerberus_native",
                    ))
                    logger.info(f"✓ [SQLi NATIVO CRITICO] Descubierto por Vector Tiempo en: {url}")

        self.findings.extend(findings)
        self.end_time = datetime.now(timezone.utc)
        return findings

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)

        return {
            "engine": "cerberus_native",
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
        }

    async def stop(self):
        logger.info("Deteniendo motor Cerberus Nativo...")
