"""
Lateral Movement Module - Sprint 2.3

Handles post-compromise network discovery, service enumeration, and pivoting.
"""
import asyncio
import logging
import shutil
import json
import ipaddress
import socket
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

    def __init__(self, method: ScanMethod = ScanMethod.CONNECT, max_hosts: int = 512):
        self.method = method
        self.max_hosts = max_hosts
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
            # Masscan mode falls back to nmap if masscan-specific parser is not enabled.
            return await self._scan_nmap(subnet, ports)
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
        """Python-based connect scan (no external dependencies)."""
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            hosts = [str(h) for h in net.hosts()]
        except ValueError:
            # Accept raw host values as single-host scan.
            hosts = [subnet.strip()]

        if not hosts:
            return []

        if len(hosts) > self.max_hosts:
            logger.warning("Subnet %s reduced from %d to %d hosts (safety cap)", subnet, len(hosts), self.max_hosts)
            hosts = hosts[: self.max_hosts]

        sem = asyncio.Semaphore(128)
        tasks = [self._scan_host_connect(sem, host, ports) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        out: List[HostInfo] = []
        for item in results:
            if isinstance(item, HostInfo):
                out.append(item)
        return out

    async def _scan_host_connect(self, sem: asyncio.Semaphore, host: str, ports: List[int]) -> Optional[HostInfo]:
        open_ports: List[int] = []
        services: Dict[int, str] = {}

        async with sem:
            for port in ports:
                if await self._is_port_open(host, port):
                    open_ports.append(port)
                    services[port] = self._guess_service(port)

        if not open_ports:
            return None

        hostname = None
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except Exception:
            hostname = None

        return HostInfo(ip=host, hostname=hostname, open_ports=open_ports, services=services)

    async def _is_port_open(self, host: str, port: int, timeout: float = 0.5) -> bool:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
            return True
        except Exception:
            return False

    @staticmethod
    def _guess_service(port: int) -> str:
        known = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http-alt",
        }
        return known.get(port, f"tcp/{port}")

class ServiceEnumerator:
    """Enumerates services to find versions and potential vulns."""
    
    async def enumerate_host(self, host: HostInfo) -> HostInfo:
        """Deep dive into a host's services."""
        for port, service in host.services.items():
            if service in ["http", "https", "http-alt"] and port in host.open_ports:
                host.vulnerabilities.extend(await self._http_checks(host.ip, port))
            elif service == "ssh":
                host.vulnerabilities.append("ssh_exposed")
            elif service == "smb":
                host.vulnerabilities.append("smb_exposed")
        return host

    async def _http_checks(self, ip: str, port: int) -> List[str]:
        findings: List[str] = []
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.0)
            writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()
            text = data.decode(errors="ignore").lower()
            if "server:" in text:
                findings.append("http_server_header_exposed")
            if "x-powered-by:" in text:
                findings.append("http_tech_stack_exposed")
        except Exception:
            pass
        return findings

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
