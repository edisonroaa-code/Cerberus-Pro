"""
Proxy Rotator - Evasion Subsystem

Manages multiple proxies and rotates them to bypass IP-based rate limiting
and WAF blacklisting. Supports HTTP/SOCKS proxies.
"""

import logging
import random
from dataclasses import dataclass, field
from typing import List, Optional
import asyncio
import time

logger = logging.getLogger("cerberus.evasion.proxy")


@dataclass
class ProxyNode:
    url: str
    proxy_type: str = "HTTP"  # HTTP, SOCKS4, SOCKS5
    is_burned: bool = False
    failure_count: int = 0
    latency_history: List[int] = field(default_factory=list)
    total_requests: int = 0
    blocked_requests: int = 0
    last_evaluation_time: float = 0
    intel_score: float = 1.0  # 1.0 = Safe, 0.0 = Honeypot


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
            
    def record_telemetry(self, url: str, latency_ms: int, was_blocked: bool):
        for p in self.pool:
            if p.url == url:
                p.total_requests += 1
                if was_blocked:
                    p.blocked_requests += 1
                if latency_ms > 0:
                    p.latency_history.append(latency_ms)
                    # Keep only last 10 for AI context
                    if len(p.latency_history) > 10:
                        p.latency_history.pop(0)
                break

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

    async def evaluate_fleet_safety(self):
        """
        [P5-D Active Threat Intel]
        Asynchronously evaluates all active proxy nodes via Cortex AI.
        Marks likely Honeypots / Blue Team sumideros as burned.
        """
        try:
            from backend.core.cortex_ai import evaluate_node_safety
            from backend.core.events import CerberusBroadcaster
        except ImportError:
            logger.warning("No se pudo importar Cortex AI para Threat Intel de Proxies.")
            return

        unburned = [p for p in self.pool if not p.is_burned]
        if not unburned:
            return

        for node in unburned:
            # Evaluate only if there is sufficient telemetry (e.g. at least 3 queries) and
            # avoid spamming (evaluate every 30 seconds at most)
            now = time.time()
            if node.total_requests >= 3 and (now - node.last_evaluation_time) > 30:
                block_rate = (node.blocked_requests / node.total_requests) if node.total_requests > 0 else 0.0
                logger.info(f"Evaluando seguridad del nodo {node.url} con Inteligencia Activa...")
                
                intel = await evaluate_node_safety(node.url, node.latency_history, block_rate)
                node.last_evaluation_time = now
                node.intel_score = intel.get("confidence", 0.5)
                
                is_safe = intel.get("is_safe", True)
                reasoning = intel.get("reasoning", "Sin justificación.")
                
                if not is_safe:
                    logger.warning(f"🚨 HONEYPOT DETECTADO por IA en {node.url}! Razón: {reasoning}")
                    self.mark_burned(node.url)
                    
                    # Notify UI
                    asyncio.create_task(
                        CerberusBroadcaster.broadcast_ws_message(
                            "CERBERUS_PRO",
                            "ai_telemetry",
                            f"🛡️ [Threat Intel] Proxy descartado {node.url} (Score: {node.intel_score:.2f}). Motivo: {reasoning}"
                        )
                    )
                else:
                    logger.debug(f"Nodo {node.url} validado seguro por IA. (Confianza: {node.intel_score:.2f})")

