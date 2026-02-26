"""
Cerberus Pro v4 - Nmap Adapter

Wraps Nmap for network reconnaissance and service discovery.
Parses XML output for exposed services and version information.
"""

import asyncio
import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict
from datetime import datetime, timezone

from .base import EngineAdapter, Finding, EngineConfig, VulnerabilityType, Severity

logger = logging.getLogger("cerberus.engines.nmap")


class NmapAdapter(EngineAdapter):
    """Wrapper around Nmap for network reconnaissance"""

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        """Run nmap for service discovery and version detection"""
        findings = []
        self.start_time = datetime.now(timezone.utc)

        # Extract IP or hostname from target URL
        import re
        match = re.search(r"(?:https?://)?([a-zA-Z0-9.-]+)", target)
        host = match.group(1) if match else target

        cmd = [
            "nmap",
            "-sV",         # Service version detection
            "-sC",         # Default scripts
            "-oX", "-",    # XML to stdout
            "--script-args", "http.useragent='Mozilla/5.0'",
            host,
        ]

        try:
            logger.info(f"[nmap] Scanning {host}...")

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=50 * 1024 * 1024,  # 50MB buffer
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(),
                    timeout=self.config.timeout_ms / 1000 + 120,
                )

                # Parse XML output
                xml_text = stdout.decode(errors="ignore")
                if xml_text:
                    root = ET.fromstring(xml_text)
                    for port_elem in root.findall(".//port"):
                        port_id = port_elem.get("portid")
                        protocol = port_elem.get("protocol", "tcp")

                        service_elem = port_elem.find("service")
                        if service_elem is not None:
                            service_name = service_elem.get("name", "unknown")
                            service_version = (
                                service_elem.get("product", "") + " " +
                                service_elem.get("version", "")
                            ).strip()

                            findings.append(Finding(
                                type=VulnerabilityType.EXPOSED_SERVICE,
                                endpoint=f"{target}:{port_id}",
                                parameter=service_name,
                                payload=f"Port {port_id}/{protocol}",
                                confidence=0.9,
                                severity=Severity.MEDIUM,
                                evidence=service_version,
                                engine="nmap",
                            ))
                            logger.info(f"✓ Service: {service_name}:{port_id}")

            except asyncio.TimeoutError:
                logger.warning(f"Nmap timeout on {host}")

        except Exception as e:
            logger.error(f"Nmap error: {e}")

        self.findings.extend(findings)
        self.end_time = datetime.now(timezone.utc)
        return findings

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)

        return {
            "engine": "nmap",
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
        }

    async def stop(self):
        logger.info("Stopping Nmap adapter")

