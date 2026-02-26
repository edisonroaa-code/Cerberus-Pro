"""
Cerberus Pro v4 - OWASP ZAP Adapter

Wraps OWASP ZAP REST API for vulnerability scanning.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import aiohttp
else:
    try:
        import aiohttp
    except ImportError:
        aiohttp = None

from .base import EngineAdapter, EngineConfig, Finding, Severity, VulnerabilityType

logger = logging.getLogger("cerberus.engines.zap")


class ZapAdapter(EngineAdapter):
    """Wrapper around OWASP ZAP REST API."""

    def __init__(self, config: EngineConfig):
        super().__init__(config)
        self.zap_url = config.custom_params.get("zap_url", "http://localhost:8080")
        self.api_key = config.custom_params.get("api_key", "")
        self.session: Optional["aiohttp.ClientSession"] = None  # type: ignore

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        self.start_time = datetime.now(timezone.utc)

        if not aiohttp:
            logger.error("aiohttp not installed, cannot use ZAP adapter")
            self.end_time = datetime.now(timezone.utc)
            return findings

        try:
            async with aiohttp.ClientSession() as session:
                self.session = session
                await self._start_passive_scan(target)
                await self._wait_for_completion()
                alerts = await self._get_alerts()

                for alert in alerts:
                    findings.append(
                        Finding(
                            type=self._map_risk_to_type(alert.get("riskcode", "3")),
                            endpoint=alert.get("url", target),
                            parameter=alert.get("param", ""),
                            payload=alert.get("attack", ""),
                            confidence=float(alert.get("confidence", 50)) / 100.0,
                            severity=self._map_severity(alert.get("riskdesc", "Medium")),
                            evidence=alert.get("description", "")[:500],
                            engine="zap",
                        )
                    )
        except Exception as e:
            logger.error("ZAP adapter error: %s", e)

        self.findings.extend(findings)
        self.end_time = datetime.now(timezone.utc)
        return findings

    async def _start_passive_scan(self, target: str):
        try:
            params = {"url": target, "apikey": self.api_key}
            async with self.session.get(
                f"{self.zap_url}/JSON/pscan/view/recordsToScan",
                params=params,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    logger.info("[ZAP] Passive scan started on %s", target)
        except Exception as e:
            logger.warning("ZAP passive scan start failed: %s", e)

    async def _wait_for_completion(self, max_wait_s: int = 60):
        for _ in range(max_wait_s):
            try:
                async with self.session.get(
                    f"{self.zap_url}/JSON/pscan/view/recordsToScan",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if int(data.get("recordsToScan", 0)) == 0:
                            logger.info("[ZAP] Scan completed")
                            return
            except Exception:
                pass
            await asyncio.sleep(2)

    async def _get_alerts(self) -> List[Dict]:
        try:
            params = {"apikey": self.api_key}
            async with self.session.get(
                f"{self.zap_url}/JSON/core/view/alerts",
                params=params,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("alerts", [])
        except Exception as e:
            logger.error("ZAP get alerts failed: %s", e)
        return []

    def _map_risk_to_type(self, riskcode: str) -> VulnerabilityType:
        if str(riskcode) == "3":
            return VulnerabilityType.SQL_INJECTION
        return VulnerabilityType.SECURITY_MISC

    def _map_severity(self, riskdesc: str) -> Severity:
        low = str(riskdesc or "").lower()
        if "critical" in low:
            return Severity.CRITICAL
        if "high" in low:
            return Severity.HIGH
        if "medium" in low:
            return Severity.MEDIUM
        return Severity.LOW

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)
        return {
            "engine": "zap",
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
            "zap_url": self.zap_url,
        }

    async def stop(self):
        logger.info("Stopping ZAP adapter")
        if self.session:
            await self.session.close()


