"""
Proxy Rotator - Evasion Subsystem

Manages multiple proxies and rotates them to bypass IP-based rate limiting
and WAF blacklisting. Supports HTTP/SOCKS proxies.
"""

import logging
import random
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("cerberus.evasion.proxy")


@dataclass
class ProxyNode:
    url: str
    proxy_type: str = "HTTP"  # HTTP, SOCKS4, SOCKS5
    is_burned: bool = False
    failure_count: int = 0


class ProxyRotator:
    """Manages a pool of proxies and provides round-robin/random selection."""
    
    def __init__(self, proxies: Optional[List[str]] = None):
        self.pool: List[ProxyNode] = []
        self._index = 0
        if proxies:
            for p in proxies:
                self.add_proxy(p)

    def add_proxy(self, url: str, proxy_type: str = "HTTP"):
        # simple check to prevent exact duplicates
        if not any(node.url == url for node in self.pool):
            self.pool.append(ProxyNode(url=url, proxy_type=proxy_type))

    def load_from_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_proxy(line)
            logger.info(f"Loaded {len(self.pool)} proxies from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load proxies from {filepath}: {e}")

    def get_next(self) -> Optional[str]:
        """Get next available proxy in round-robin fashion."""
        available = [p for p in self.pool if not p.is_burned]
        if not available:
            return None
            
        proxy = available[self._index % len(available)]
        self._index += 1
        return proxy.url

    def mark_burned(self, url: str):
        """Mark a proxy as burned (rate limited / blocked) so it won't be used."""
        for p in self.pool:
            if p.url == url:
                p.is_burned = True
                logger.warning(f"Proxy burned and excluded: {url}")
                break

    def get_sqlmap_args(self) -> List[str]:
        """Generate sqlmap arguments for the currently available proxies."""
        available = [p.url for p in self.pool if not p.is_burned]
        if not available:
            return []
            
        # sqlmap supports passing a list of proxies to cycle through
        proxy_list = ",".join(available)
        return [f"--proxy={proxy_list}", "--random-agent"]
