#!/usr/bin/env python3
"""
CERBERUS Pro - Unified Launcher
Starts all services in one command
"""

import subprocess
import sys
import os
import time
from pathlib import Path
import platform
import signal

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

class AresLauncher:
    def __init__(self):
        self.processes = []
        self.root_dir = Path(__file__).parent
        if load_dotenv is not None:
            load_dotenv(self.root_dir / ".env")
        self.certs_dir = self.root_dir / "certs"
        self.backend_host = os.environ.get("API_HOST", "127.0.0.1")
        self.backend_port = int(os.environ.get("API_PORT", "8011") or "8011")
        self.backend_base_url = None
        self.ws_base_url = None
        
    def generate_self_signed_cert(self):
        """Generate self-signed certificate for local HTTPS/WSS"""
        cert_file = self.certs_dir / "cert.pem"
        key_file = self.certs_dir / "key.pem"
        
        if cert_file.exists() and key_file.exists():
            return True
            
        print("\n[*] Generating self-signed certificates for WSS/TLS...")
        self.certs_dir.mkdir(exist_ok=True)
        
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate cert
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PY"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Central"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Asuncion"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cerberus Pro"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 1 year
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            ).sign(key, hashes.SHA256())
            
            # Write key
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
                
            # Write cert
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                
            print(f"   [OK] Certificates generated in {self.certs_dir}")
            return True
        except Exception as e:
            print(f"   [ERROR] Failed to generate certificates: {e}")
            print("   Please install 'cryptography' or provide certs manually in /certs directory.")
            return False
        print("""
===============================================================
                                                           
   CERBERUS PRO v3.1.0 - Unified Launcher         
   Enterprise Security Edition               
                                                           
===============================================================
        """)
        
    def check_python_version(self):
        """Check if Python version is compatible"""
        if sys.version_info < (3, 9):
            print("❌ ERROR: Python 3.9+ required")
            print(f"   Current version: {sys.version}")
            return False
        return True
        
    def check_node_installed(self):
        """Check if Node.js and npm are installed"""
        try:
            # Try multiple methods to find npm on Windows
            if platform.system() == "Windows":
                # Method 1: Try with shell (inherits full PATH)
                result = subprocess.run(
                    "npm --version", 
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return True
                    
                # Method 2: Try common Windows paths
                npm_paths = [
                    "npm",
                    "npm.cmd",
                    os.path.expandvars(r"%ProgramFiles%\nodejs\npm.cmd"),
                    os.path.expandvars(r"%APPDATA%\npm\npm.cmd")
                ]
                
                for npm_path in npm_paths:
                    try:
                        result = subprocess.run(
                            [npm_path, "--version"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            return True
                    except:
                        continue
            else:
                # Unix-like systems
                result = subprocess.run(
                    ["npm", "--version"], 
                    check=True, 
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return True
                
        except Exception as e:
            pass
            
        print("❌ ERROR: npm not found or not accessible")
        print("   If you ran 'npm start', this is a PATH issue.")
        print("   Try running: python start_cerberus.py")
        return False

            
    def start_backend(self):
        """Start FastAPI backend"""
        print("\n[1/2] Starting Backend (FastAPI)...")
        
        # Check if uvicorn is installed
        try:
            import uvicorn
        except ImportError:
            print("   ⚠️  uvicorn not found. Installing dependencies...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "backend/requirements_secure.txt"],
                cwd=self.root_dir
            )
        
        # Start backend process
        cmd = [
            sys.executable, "-m", "uvicorn", "backend.ares_api:app",
            "--host", self.backend_host, "--port", str(self.backend_port), "--reload"
        ]
        
        cert_file = self.certs_dir / "cert.pem"
        key_file = self.certs_dir / "key.pem"
        
        use_ssl = cert_file.exists() and key_file.exists()
        if use_ssl:
            cmd.extend(["--ssl-keyfile", str(key_file), "--ssl-certfile", str(cert_file)])
            
        backend_proc = subprocess.Popen(
            cmd,
            cwd=self.root_dir,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0,
            env={**os.environ, "ENVIRONMENT": "development"}
        )
        
        self.processes.append(("Backend", backend_proc))
        
        # Wait for backend to be ready
        print("   [*] Waiting for backend to start...")
        time.sleep(3)
        
        if backend_proc.poll() is not None:
            print("   [ERROR] Backend failed to start")
            return None
            
        protocol = "https" if use_ssl else "http"
        self.backend_base_url = f"{protocol}://{self.backend_host}:{self.backend_port}"
        self.ws_base_url = f"{'wss' if use_ssl else 'ws'}://{self.backend_host}:{self.backend_port}"
        print(f"   [OK] Backend started on {protocol}://{self.backend_host}:{self.backend_port}")
        return backend_proc
        
    def start_frontend(self):
        """Start Vite frontend"""
        print("\n[2/2] Starting Frontend (Vite)...")
        
        # Check if node_modules exists
        node_modules = self.root_dir / "node_modules"
        if not node_modules.exists():
            print("   [*] node_modules not found. Running npm install...")
            subprocess.run(["npm", "install"], cwd=self.root_dir, check=True)
            
        # Start frontend process
        env = {**os.environ}
        # Ensure frontend points to the same protocol (http/https, ws/wss) as the backend.
        if self.backend_base_url:
            env["VITE_API_URL"] = str(self.backend_base_url)
        if self.ws_base_url:
            env["VITE_WS_URL"] = str(self.ws_base_url)

        if platform.system() == "Windows":
            frontend_proc = subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=self.root_dir,
                shell=True,  # Windows needs shell for npm
                env=env,
            )
        else:
            frontend_proc = subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=self.root_dir,
                env=env,
            )
        
        self.processes.append(("Frontend", frontend_proc))
        
        # Wait for frontend to be ready
        print("   [*] Waiting for frontend to start...")
        time.sleep(4)
        
        if frontend_proc.poll() is not None:
            print("   [ERROR] Frontend failed to start")
            return None
            
        print("   [OK] Frontend started on http://localhost:5173")
        return frontend_proc
        
    def monitor_processes(self):
        """Monitor processes and wait for Ctrl+C"""
        print("\n" + "="*60)
        print("*** CERBERUS is running! ***")
        print("="*60)
        print("\n>> Access the application at: http://localhost:5173")
        print(f">> API Documentation at: http://{self.backend_host}:{self.backend_port}/docs")
        print("\n>> Press Ctrl+C to stop all services\n")
        print("="*60 + "\n")
        
        try:
            while True:
                # Check if any process died
                for name, proc in self.processes:
                    if proc.poll() is not None:
                        print(f"\n[ERROR] {name} process died unexpectedly!")
                        self.cleanup()
                        return False
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\n>> Shutting down CERBERUS...")
            self.cleanup()
            return True
            
    def cleanup(self):
        """Terminate all processes gracefully"""
        if getattr(self, 'shutting_down', False):
            return
        self.shutting_down = True
        
        print("\n>> Stopping all services...")
        
        for name, proc in reversed(self.processes):  # Stop in reverse order
            if proc.poll() is None:  # Only if still running
                print(f"   Stopping {name}...")
                
                try:
                    # Generic kill first
                    if platform.system() == "Windows":
                        proc.send_signal(signal.CTRL_C_EVENT if hasattr(signal, 'CTRL_C_EVENT') else signal.SIGTERM)
                    else:
                        proc.terminate()
                    
                    try:
                        proc.wait(timeout=3)
                        print(f"   [OK] {name} stopped")
                    except subprocess.TimeoutExpired:
                        print(f"   [WARN] Force killing {name}...")
                        
                        if platform.system() == "Windows":
                            # Windows: Force kill whole process tree
                            subprocess.run(f"taskkill /F /T /PID {proc.pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        else:
                            proc.kill()
                            
                        print(f"   [OK] {name} killed")
                        
                except Exception as e:
                    print(f"   [WARN] Error stopping {name}: {e}")
                    
        print("\n[OK] CERBERUS stopped successfully\n")
        
    def run(self):
        """Main launcher logic"""
        self.print_banner()
        
        # Check requirements
        if not self.check_python_version():
            sys.exit(1)
            
        if not self.check_node_installed():
            sys.exit(1)
            
        # Start services
        self.generate_self_signed_cert()
        backend = self.start_backend()
        if not backend:
            print("\n❌ Failed to start backend")
            self.cleanup()
            sys.exit(1)
            
        frontend = self.start_frontend()
        if not frontend:
            print("\n❌ Failed to start frontend")
            self.cleanup()
            sys.exit(1)
            
        # Monitor
        success = self.monitor_processes()
        
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    launcher = AresLauncher()
    
    # Register signal handlers
    def signal_handler(sig, frame):
        launcher.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Run launcher
    launcher.run()
