"""
Cerberus Pro v4 - Custom Payload Adapter

Injects custom payloads and detects vulnerability indicators.
Fast parallel testing of payloads against discovered parameters.
"""

import asyncio
import logging
from typing import List, Dict, Optional, TYPE_CHECKING
from datetime import datetime, timezone

if TYPE_CHECKING:
    import aiohttp
else:
    try:
        import aiohttp
    except ImportError:
        aiohttp = None

from .base import EngineAdapter, Finding, EngineConfig, VulnerabilityType, Severity

logger = logging.getLogger("cerberus.engines.custom_payload")


class CustomPayloadAdapter(EngineAdapter):
    """Inject and test custom payloads for vulnerability detection"""

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        """Test payloads in parallel"""
        findings = []
        self.start_time = datetime.now(timezone.utc)

        if not aiohttp:
            logger.error("aiohttp not installed, cannot use custom payload adapter")
            self.end_time = datetime.now(timezone.utc)
            return findings

        async with aiohttp.ClientSession() as session:
            tasks = []

            for vector in vectors:
                endpoint = vector.get("endpoint", "/")
                parameter = vector.get("parameter", "id")
                payloads = vector.get("payloads", [
                    "test",
                    "' OR '1'='1",
                    "1 UNION SELECT 1",
                    "<script>alert(1)</script>",
                    "../../../etc/passwd",
                ])

                for payload in payloads[:self.config.max_payloads]:
                    tasks.append(
                        self._test_payload(
                            session, target, endpoint, parameter, payload
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

    async def _test_payload(
        self,
        session: "aiohttp.ClientSession",  # type: ignore
        target: str,
        endpoint: str,
        parameter: str,
        payload: str,
    ) -> Optional[Finding]:
        """Test single payload and detect response anomalies"""
        try:
            url = f"{target}{endpoint}"

            # Prepare params based on common patterns
            params = {parameter: payload}

            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=5),
                headers={"User-Agent": "Mozilla/5.0"},
                ssl=False,
            ) as resp:
                text = await resp.text()

                # Simple vulnerability indicators
                indicators = {
                    "error": ["error in", "syntax error", "exception", "warning"],
                    "sqli": [
                        "sql",
                        "mysql_fetch",
                        "postgresql",
                        "database error",
                    ],
                    "xss": ["<script>", "javascript:", "onerror="],
                    "rce": ["uid=", "root@", "www-data"],
                    "traversal": ["/etc/passwd", "root:"],
                }

                text_lower = text.lower()

                for vuln_type, keywords in indicators.items():
                    for keyword in keywords:
                        if keyword in text_lower:
                            confidence = 0.6
                            if keyword in payload.lower():
                                confidence = 0.3  # Echo-based, lower conf
                            if resp.status >= 400:
                                confidence = 0.4  # Error response

                            return Finding(
                                type=self._map_type(vuln_type),
                                endpoint=endpoint,
                                parameter=parameter,
                                payload=payload,
                                confidence=confidence,
                                severity=Severity.MEDIUM,
                                evidence=text[:300],
                                engine="custom_payload",
                            )

        except asyncio.TimeoutError:
            logger.debug(f"Payload timeout: {endpoint}?{parameter}={payload}")
        except Exception as e:
            logger.debug(f"Payload test error: {e}")

        return None

    def _map_type(self, vuln_type: str) -> VulnerabilityType:
        """Map vulnerability type string to enum"""
        type_map = {
            "error": VulnerabilityType.SECURITY_MISC,
            "sqli": VulnerabilityType.SQL_INJECTION,
            "xss": VulnerabilityType.XSS,
            "rce": VulnerabilityType.RCE,
            "traversal": VulnerabilityType.PATH_TRAVERSAL,
        }
        return type_map.get(vuln_type, VulnerabilityType.SECURITY_MISC)

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)

        return {
            "engine": "custom_payload",
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
        }

    async def stop(self):
        logger.info("Stopping custom payload adapter")

