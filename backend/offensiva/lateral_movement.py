"""
Lateral Movement Module - Sprint 2.3

Handles post-compromise network discovery, service enumeration, and pivoting.
"""
import asyncio
import logging
import shutil
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum

logger = logging.getLogger("cerberus.offensiva.lateral")

class ScanMethod(str, Enum):
    NMAP = "nmap"
    MASSCAN = "masscan"
    CONNECT = "connect"  # Python socket connect (slower but no deps)

@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)

class NetworkScanner:
    """Scans internal networks for live hosts and open ports."""

    def __init__(self, method: ScanMethod = ScanMethod.CONNECT):
        self.method = method
        self._check_deps()

    def _check_deps(self):
        if self.method == ScanMethod.NMAP and not shutil.which("nmap"):
            logger.warning("nmap not found, falling back to connect scan")
            self.method = ScanMethod.CONNECT
        if self.method == ScanMethod.MASSCAN and not shutil.which("masscan"):
            logger.warning("masscan not found, falling back to connect scan")
            self.method = ScanMethod.CONNECT

    async def scan_subnet(self, subnet: str, ports: List[int] = None) -> List[HostInfo]:
        """Scan a subnet for live hosts."""
        logger.info(f"Scanning subnet {subnet} using {self.method}")
        
        if not ports:
            ports = [21, 22, 80, 443, 445, 3306, 3389, 5432, 8080]

        if self.method == ScanMethod.NMAP:
            return await self._scan_nmap(subnet, ports)
        elif self.method == ScanMethod.MASSCAN:
            # Placeholder for masscan implementation
            return await self._scan_nmap(subnet, ports)  # Fallback
        else:
            return await self._scan_connect(subnet, ports)

    async def _scan_nmap(self, subnet: str, ports: List[int]) -> List[HostInfo]:
        """Wrapper around nmap."""
        port_str = ",".join(map(str, ports))
        # Simplification: -sS needs root, -sT (connect) does not.
        cmd = f"nmap -sT -p {port_str} --open {subnet}"
        
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            logger.error(f"Nmap failed: {stderr.decode()}")
            return []
            
        output = stdout.decode()
        hosts = self._parse_nmap_text(output)
        return hosts

    def _parse_nmap_text(self, output: str) -> List[HostInfo]:
        """Parse basic Nmap text output."""
        hosts = []
        current_host = None
        
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                if current_host:
                    hosts.append(current_host)
                # Extract IP "Nmap scan report for localhost (127.0.0.1)" or just "192.168.1.1"
                parts = line.split()
                ip_part = parts[-1].strip("()")
                current_host = HostInfo(ip=ip_part)
            
            if current_host and "/tcp" in line and "open" in line:
                # 22/tcp open  ssh
                parts = line.split("/")
                port = int(parts[0])
                service = line.split()[-1]
                current_host.open_ports.append(port)
                current_host.services[port] = service
                
        if current_host:
            hosts.append(current_host)
            
        return hosts

    async def _scan_connect(self, subnet: str, ports: List[int]) -> List[HostInfo]:
        """Python-based connect scan (slow but works everywhere)."""
        # Note: subnet scanning in pure python requires generating IPs.
        # This is a stub for the "fallback" mode.
        logger.warning("Connect scan for subnets not fully implemented in stub.")
        return []

class ServiceEnumerator:
    """Enumerates services to find versions and potential vulns."""
    
    async def enumerate_host(self, host: HostInfo) -> HostInfo:
        """Deep dive into a host's services."""
        for port, service in host.services.items():
            if service in ["http", "https", "http-alt"]:
                # Trigger web recon (lightweight)
                pass
            elif service == "ssh":
                # Check auth methods
                pass
            elif service == "smb":
                # Check signing, null session
                pass
        return host

class LateralOrchestrator:
    """Orchestrates the lateral movement logic."""
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.enumerator = ServiceEnumerator()
        self.compromised_hosts: Set[str] = set()
        
    async def explore_network(self, starting_subnet: str) -> List[HostInfo]:
        """Auto-discover neighbors."""
        hosts = await self.scanner.scan_subnet(starting_subnet)
        
        results = []
        for host in hosts:
            detailed = await self.enumerator.enumerate_host(host)
            results.append(detailed)
            
        return results
