"""
Cerberus Pro v4 - SQLMap Adapter

Wraps sqlmap command-line tool for SQL injection detection.
Async subprocess execution with JSON output parsing.
"""

import asyncio
import subprocess
import json
import logging
import os
from typing import List, Dict
from datetime import datetime, timezone
from .base import EngineAdapter, Finding, EngineConfig, VulnerabilityType, Severity

logger = logging.getLogger("cerberus.engines.sqlmap")


class SqlmapAdapter(EngineAdapter):
    """Wrapper around sqlmap CLI for SQL injection testing"""

    def __init__(self, config: EngineConfig):
        super().__init__(config)
        # Find sqlmap path
        self.sqlmap_path = self._find_sqlmap()

    def _find_sqlmap(self) -> str:
        """Find sqlmap executable or script"""
        # Try common locations
        candidates = [
            "sqlmap",  # In PATH
            "./sqlmap-master/sqlmap.py",
            "../sqlmap-master/sqlmap.py",
            os.path.join(os.path.dirname(__file__), "../../sqlmap-master/sqlmap.py"),
            os.path.join(os.getcwd(), "sqlmap-master", "sqlmap.py"),
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
        ]
        
        for candidate in candidates:
            if os.path.exists(candidate) or candidate in ["sqlmap", "/usr/bin/sqlmap", "/usr/local/bin/sqlmap"]:
                logger.debug(f"Motor SQLMap encontrado en: {candidate}")
                return candidate
        
        logger.warning("Motor SQLMap no encontrado en rutas estándar, se intentará usar comando global 'sqlmap'")
        return "sqlmap"

    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        """Execute sqlmap against target with aggressive settings"""
        findings = []
        self.start_time = datetime.now(timezone.utc)

        if not vectors:
            logger.warning("No se proporcionaron vectores de ataque al motor SQLMap")
            self.end_time = datetime.now(timezone.utc)
            return findings

        for idx, vector in enumerate(vectors):
            if not self.config.enabled:
                break

            endpoint = vector.get("endpoint", "/")
            parameter = vector.get("parameter", "id")
            method = vector.get("method", "GET")

            # Build sqlmap command with aggressive settings
            url = f"{target}{endpoint}"
            if method == "GET":
                url += f"?{parameter}=1"

            # Use python if sqlmap is a script, otherwise use direct command
            cmd_base = [self.sqlmap_path if not self.sqlmap_path.endswith(".py") else "python"]
            if self.sqlmap_path.endswith(".py"):
                cmd_base.append(self.sqlmap_path)
            
            # Build aggressive command for better detection
            cmd = cmd_base + [
                "-u", url,
                "-X", method,
                "--batch",
                "--threads=3",
                "--level=5",           # MAX level for parameter detection
                "--risk=3",            # MAX risk for technique testing
                "--technique=BESTQU",  # Boolean, Error-based, Stacked, Time-based, UNION Query
                "-p", parameter,
                "--tamper=between,base64encode,randomcase,charencode,space2comment",  # Evasion
                "--random-agent",      # Random User-Agent
                "--hpp",               # HTTP Parameter Pollution
                "--hex",               # HEX encoding for strings
                "--keep-alive",        # Use persistent HTTP connections
                f"--timeout={self.config.timeout_ms / 1000:.0f}",
            ]

            try:
                logger.info(f"[{endpoint}] Auditando parámetro '{parameter}' (Modo Agresivo)...")

                # Run sqlmap subprocess
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=50 * 1024 * 1024,  # 50MB buffer for verbose output
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        result.communicate(),
                        timeout=min(self.config.timeout_ms / 1000 + 60, 300),  # Max 5 min
                    )

                    # Parse text output
                    output_text = stdout.decode('utf-8', errors='ignore')
                    stderr_text = stderr.decode('utf-8', errors='ignore') if stderr else ""
                    
                    is_vulnerable = False
                    evidence_lines = []
                    
                    # Check for vulnerability indicators in output
                    all_text = output_text + "\n" + stderr_text
                    for line in all_text.split('\n'):
                        line_lower = line.lower()
                        
                        # PRIMARY: Direct vulnerability claims
                        if any(keyword in line_lower for keyword in [
                            "is vulnerable to",
                            "appears to be vulnerable",
                            "is vulnerable",
                            "appears to be injectable",
                            "identified the following injection",
                            "is likely vulnerable",
                            "injectable",
                        ]):
                            is_vulnerable = True
                            if line.strip():
                                evidence_lines.append(line.strip())
                        
                        # SECONDARY: Evidence of successful exploitation
                        elif any(keyword in line_lower for keyword in [
                            "[*] retrieved",
                            "current user:",
                            "current database:",
                            "database:",
                            "[+]",
                            "payload:",
                            "parameter '",
                            "parameter_used:",
                        ]):
                            if line.strip() and line.strip() not in evidence_lines:
                                evidence_lines.append(line.strip())
                        
                        # TERTIARY: Detected techniques
                        elif any(keyword in line_lower for keyword in [
                            "time-based blind",
                            "boolean-based blind",
                            "error-based",
                            "stacked queries",
                            "union query",
                        ]):
                            is_vulnerable = True
                            if line.strip():
                                evidence_lines.append(line.strip())

                    # If vulnerability found, create finding with HIGH confidence
                    if is_vulnerable:
                        findings.append(Finding(
                            type=VulnerabilityType.SQL_INJECTION,
                            endpoint=endpoint,
                            parameter=parameter,
                            payload=evidence_lines[0] if evidence_lines else "SQLi detected",
                            confidence=0.95,
                            severity=Severity.CRITICAL,
                            evidence="\n".join(evidence_lines[:5])[:1000],
                            engine="sqlmap",
                        ))
                        logger.info(f"✓ [SQLi CRÍTICO] Descubierto en: {endpoint}/{parameter}")
                    else:
                        # Log diagnosis
                        if "no parameters tested" in output_text.lower():
                            logger.info(f"⚠ [{endpoint}] Sin parámetros detectables para inyección")
                        elif "all tested parameters do not appear" in output_text.lower():
                            logger.info(f"✗ [{endpoint}/{parameter}] Seguro contra SQLi - Avanzando...")
                        else:
                            logger.info(f"❓ [{endpoint}/{parameter}] Resultado difuso - Requiere revisión heurística")

                except asyncio.TimeoutError:
                    logger.warning(f"[{endpoint}] Tiempo de espera agotado (Timeout).")

            except Exception as e:
                logger.error(f"[{endpoint}] Error crítico en motor: {e}")

        self.findings.extend(findings)
        self.end_time = datetime.now(timezone.utc)
        return findings

    def get_status(self) -> Dict:
        duration = 0
        if self.start_time and self.end_time:
            duration = int((self.end_time - self.start_time).total_seconds() * 1000)

        return {
            "engine": "sqlmap",
            "status": "ready",
            "findings": len(self.findings),
            "duration_ms": duration,
        }

    async def stop(self):
        logger.info("Deteniendo adaptador SQLMap de manera segura...")

