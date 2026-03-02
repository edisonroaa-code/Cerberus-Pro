from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Optional, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    import aiohttp
else:
    try:
        import aiohttp
    except ImportError:
        aiohttp = None

from .base import EngineAdapter, EngineConfig, Finding
from .base import VulnerabilityType, Severity


logger = logging.getLogger("cerberus.engines.burp")


class BurpAdapter(EngineAdapter):
    def __init__(self, config: EngineConfig):
        super().__init__(config)
        self.burp_url = config.custom_params.get("burp_url", "http://127.0.0.1:1337")
        self.proxy_requests = bool(config.custom_params.get("use_proxy", True))
        self._stopped = False

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        self.findings = []
        self.start_time = datetime.now(timezone.utc)
        self._stopped = False

        if not aiohttp:
            logger.error("aiohttp not installed, cannot use Burp adapter")
            self.end_time = datetime.now(timezone.utc)
            return findings

        if not vectors:
            vectors = [{"endpoint": "/", "parameter": "id", "payloads": ["1", "1' OR '1'='1"]}]

        sem = asyncio.Semaphore(max(1, min(40, int(self.config.rate_limit_rps * 4))))
        tasks = []
        timeout = aiohttp.ClientTimeout(total=max(3, int(self.config.timeout_ms / 1000)))

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for vector in vectors:
                if self._stopped:
                    break
                endpoint = str(vector.get("endpoint") or "/")
                parameter = str(vector.get("parameter") or vector.get("param_name") or "id")
                payloads = vector.get("payloads") or ["1", "1' OR '1'='1", "<script>alert(1)</script>", "../../../../etc/passwd"]
                limit = max(1, min(len(payloads), self.config.max_payloads))
                for payload in payloads[:limit]:
                    tasks.append(
                        self._probe_vector(
                            sem=sem,
                            session=session,
                            target=target,
                            endpoint=endpoint,
                            parameter=parameter,
                            payload=str(payload),
                        )
                    )

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                logger.debug("BurpAdapter probe error: %s", result)

        self.findings.extend(findings)
        self.end_time = datetime.now(timezone.utc)
        return findings

    async def _probe_vector(
        self,
        sem: asyncio.Semaphore,
        session: "aiohttp.ClientSession",
        target: str,
        endpoint: str,
        parameter: str,
        payload: str,
    ) -> Optional[Finding]:
        if self._stopped:
            return None
        async with sem:
            url = f"{target.rstrip('/')}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
            req_kwargs: Dict[str, object] = {
                "params": {parameter: payload},
                "headers": {
                    "User-Agent": "Mozilla/5.0 Cerberus-BurpAdapter",
                    "Accept": "*/*",
                },
                "allow_redirects": True,
                "ssl": False,
            }
            if self.proxy_requests and self.burp_url:
                req_kwargs["proxy"] = self.burp_url

            try:
                async with session.get(url, **req_kwargs) as resp:
                    text = await resp.text(errors="ignore")
                    return self._analyze_response(
                        endpoint=endpoint,
                        parameter=parameter,
                        payload=payload,
                        status=resp.status,
                        response_text=text,
                    )
            except Exception:
                return None

    def _analyze_response(
        self,
        endpoint: str,
        parameter: str,
        payload: str,
        status: int,
        response_text: str,
    ) -> Optional[Finding]:
        low = response_text.lower()

        if any(k in low for k in ("sql syntax", "warning: mysql", "unterminated quoted string", "sqlite error", "postgresql")):
            return Finding(
                type=VulnerabilityType.SQL_INJECTION,
                endpoint=endpoint,
                parameter=parameter,
                payload=payload,
                confidence=0.82 if status >= 400 else 0.68,
                severity=Severity.HIGH,
                evidence=[response_text[:400]],
                engine="burp",
            )

        if payload and payload.lower() in low and any(x in payload.lower() for x in ("<script", "onerror=", "javascript:")):
            return Finding(
                type=VulnerabilityType.XSS,
                endpoint=endpoint,
                parameter=parameter,
                payload=payload,
                confidence=0.75,
                severity=Severity.HIGH,
                evidence=["Payload reflected in response body"],
                engine="burp",
            )

        if any(k in low for k in ("root:x:0:0:", "/etc/passwd", "windows\\system32", "[boot loader]")):
            return Finding(
                type=VulnerabilityType.PATH_TRAVERSAL,
                endpoint=endpoint,
                parameter=parameter,
                payload=payload,
                confidence=0.9,
                severity=Severity.HIGH,
                evidence=[response_text[:400]],
                engine="burp",
            )

        if status >= 500:
            return Finding(
                type=VulnerabilityType.SECURITY_MISC,
                endpoint=endpoint,
                parameter=parameter,
                payload=payload,
                confidence=0.4,
                severity=Severity.MEDIUM,
                evidence=[f"Server returned {status}"],
                engine="burp",
            )

        return None

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)
        return {
            "engine": self.config.engine_id,
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
            "errors": 0,
            "burp_proxy": self.burp_url,
        }

    async def stop(self):
        self._stopped = True
