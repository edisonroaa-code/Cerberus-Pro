"""
Cerberus Pro v4 - Payload Mutation v2 Integration with Custom Payload Adapter

Enhanced custom payload engine using advanced mutation strategies.
"""

import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone

try:
    import aiohttp
except ImportError:
    aiohttp = None

from backend.engines.base import EngineAdapter, Finding, EngineConfig, VulnerabilityType, Severity
from backend.core.payload_mutation_v2 import PayloadMutationEngine, AdaptivePayloadMutator

logger = logging.getLogger("cerberus.engines.advanced_payload")


class AdvancedPayloadAdapter(EngineAdapter):
    """Enhanced custom payload adapter with mutation engine v2"""

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        """Test mutated payloads with adaptive learning"""
        findings = []
        self.start_time = datetime.now(timezone.utc)

        if not aiohttp:
            logger.error("aiohttp not installed, cannot use advanced payload adapter")
            self.end_time = datetime.now(timezone.utc)
            return findings

        async with aiohttp.ClientSession() as session:
            tasks = []

            for vector in vectors:
                endpoint = vector.get("endpoint", "/")
                parameter = vector.get("parameter", "id")
                base_payloads = vector.get("payloads", [
                    "test",
                    "1' OR '1'='1",
                    "<script>alert(1)</script>",
                    "../../../etc/passwd",
                ])

                # For each base payload, generate mutations
                for base_payload in base_payloads[:max(1, self.config.max_payloads // 10)]:
                    mutator = PayloadMutationEngine(base_payload, mutation_level=self.config.custom_params.get("mutation_level", 2))

                    # [P5-A] Probe target to get error trace context for Cortex AI
                    probe_payload = base_payload + "'"
                    error_trace = ""
                    try:
                        async with session.get(
                            f"{target}{endpoint}",
                            params={parameter: probe_payload},
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False
                        ) as probe_resp:
                            resp_text = await probe_resp.text()
                            if probe_resp.status >= 500 or any(kw in resp_text.lower() for kw in ["syntax", "error", "exception", "traceback"]):
                                error_trace = resp_text[:2000]  # Grab trace
                                logger.debug(f"Captured error trace for AI context on {endpoint}")
                    except Exception as e:
                        logger.debug(f"Probe error: {e}")

                    # [P5-A] Generate smart variants with Gemini (falls back to heuristic)
                    mutations = await mutator.generate_smart_variants(
                        context={"vector": "Custom", "url": target, "parameter": parameter, "dbms": "Auto", "os": "Auto"},
                        error_trace=error_trace,
                        target_count=min(100, max(5, self.config.max_payloads // len(base_payloads)))
                    )

                    for mutation in mutations:
                        tasks.append(
                            self._test_payload_with_feedback(
                                session, target, endpoint, parameter, mutation
                            )
                        )

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Finding):
                    findings.append(result)
                elif isinstance(result, Exception):
                    logger.debug(f"Payload test exception: {result}")

        self.findings.extend(findings)
        self.end_time = datetime.now(timezone.utc)
        return findings

    async def _test_payload_with_feedback(
        self,
        session: "aiohttp.ClientSession",  # type: ignore
        target: str,
        endpoint: str,
        parameter: str,
        payload: str,
    ) -> Optional[Finding]:
        """Test single mutation with adaptive feedback"""
        import json
        from backend.core.events import CerberusBroadcaster
        
        try:
            url = f"{target}{endpoint}"
            params = {parameter: payload}
            
            method = "GET"
            req_kwargs = {
                "timeout": aiohttp.ClientTimeout(total=5),
                "headers": {"User-Agent": "Mozilla/5.0"},
                "ssl": False,
            }

            # [P5-B] Semantic Evasion
            if self.config.custom_params.get("mutation_level", 2) >= 3:
                from backend.core.cortex_ai import generate_semantic_camouflage
                await CerberusBroadcaster.broadcast_ws_message("CERBERUS_PRO", "ai_telemetry", f"🎭 [Cortex AI] Aplicando Semantic Evasion para camuflar payload en {endpoint}...")
                
                camouflaged_json = await generate_semantic_camouflage(
                    payload, {"url": url, "parameter": parameter}
                )
                
                if camouflaged_json:
                    await CerberusBroadcaster.broadcast_ws_message("CERBERUS_PRO", "ai_telemetry", f"  > ¡Camuflaje Completo! Transportando payload oculto vía POST JSON.")
                    method = "POST"
                    req_kwargs["headers"]["Content-Type"] = "application/json"
                    req_kwargs["data"] = camouflaged_json
                else:
                    await CerberusBroadcaster.broadcast_ws_message("CERBERUS_PRO", "ai_telemetry", f"⚠️ Fallo al generar camuflaje semántico. Fallback a inyección GET bruta.")
                    req_kwargs["params"] = params
            else:
                req_kwargs["params"] = params

            async with session.request(
                method,
                url,
                **req_kwargs
            ) as resp:
                text = await resp.text()

                # Analyze response with adaptive learning
                finding = self._analyze_response_advanced(
                    text, resp.status, endpoint, parameter, payload
                )

                return finding

        except asyncio.TimeoutError:
            logger.debug(f"Payload timeout: {endpoint}?{parameter}={payload}")
        except Exception as e:
            logger.debug(f"Payload test error: {e}")

        return None

    def _analyze_response_advanced(
        self, response_text: str, status_code: int, endpoint: str, parameter: str, payload: str
    ) -> Optional[Finding]:
        """Advanced response analysis with multiple indicators"""

        # Normalize response for analysis
        text_lower = response_text.lower()

        # SQL Injection indicators
        sql_keywords = [
            "sql syntax", "mysql_fetch", "unexpected token", "sql error",
            "postgresql", "odbc", "driver", "database error", "sql exception"
        ]
        for keyword in sql_keywords:
            if keyword in text_lower:
                return Finding(
                    type=VulnerabilityType.SQL_INJECTION,
                    endpoint=endpoint,
                    parameter=parameter,
                    payload=payload,
                    confidence=0.85 if status_code >= 400 else 0.70,
                    severity=Severity.CRITICAL,
                    evidence=response_text[:500],
                    engine="advanced_payload",
                )

        # XSS indicators
        xss_keywords = ["<script>", "javascript:", "onerror=", "onload=", "onclick="]
        for keyword in xss_keywords:
            if keyword in response_text:
                if keyword in payload:
                    confidence = 0.65  # Echo-based, lower confidence
                else:
                    confidence = 0.90  # Stored, higher confidence
                
                return Finding(
                    type=VulnerabilityType.XSS,
                    endpoint=endpoint,
                    parameter=parameter,
                    payload=payload,
                    confidence=confidence,
                    severity=Severity.HIGH,
                    evidence=response_text[:500],
                    engine="advanced_payload",
                )

        # RCE indicators
        rce_keywords = ["uid=", "gid=", "groups=", "root:", "www-data", "/bin/sh"]
        for keyword in rce_keywords:
            if keyword in response_text:
                return Finding(
                    type=VulnerabilityType.RCE,
                    endpoint=endpoint,
                    parameter=parameter,
                    payload=payload,
                    confidence=0.95,
                    severity=Severity.CRITICAL,
                    evidence=response_text[:500],
                    engine="advanced_payload",
                )

        # Path traversal indicators
        traversal_keywords = ["/etc/passwd", "root:x:0:0", "/etc/shadow", "Windows/System32"]
        for keyword in traversal_keywords:
            if keyword in response_text:
                return Finding(
                    type=VulnerabilityType.PATH_TRAVERSAL,
                    endpoint=endpoint,
                    parameter=parameter,
                    payload=payload,
                    confidence=0.95,
                    severity=Severity.HIGH,
                    evidence=response_text[:500],
                    engine="advanced_payload",
                )

        # Generic error indicators
        if status_code >= 500:
            return Finding(
                type=VulnerabilityType.SECURITY_MISC,
                endpoint=endpoint,
                parameter=parameter,
                payload=payload,
                confidence=0.45,
                severity=Severity.MEDIUM,
                evidence=f"Server error ({status_code})",
                engine="advanced_payload",
            )

        return None

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)

        return {
            "engine": "advanced_payload",
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
            "mutation_level": self.config.custom_params.get("mutation_level", 2),
        }

    async def stop(self):
        logger.info("Stopping advanced payload adapter")

