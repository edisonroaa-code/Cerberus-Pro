/**
 * ARCH-001: Extracted from App.tsx
 * Remote agent Python script template.
 */

export const AGENT_SCRIPT = `
import asyncio
import websockets
import json
import subprocess
import sys

# Configuración
C2_URL = "ws://localhost:8000/ws" # URL del Servidor Websocket Cerberus
TARGET_ENGINE = "cerberus_pro" # Nombre lógico del motor (ajustar si necesita ruta)

async def run_agent():
    print(f"[*] Conectando Agente Cerberus a {C2_URL}...")
    async with websockets.connect(C2_URL) as websocket:
        print("[+] Conectado. Esperando órdenes.")
        
        async for message in websocket:
            data = json.loads(message)
            
            if data['action'] == 'start':
                config = data['config']
                sql_config = config['sqlMap']
                
                cmd = [
                    TARGET_SQLMAP, 
                    "-u", config['url'],
                    "--batch",
                    f"--threads={sql_config['threads']}",
                    f"--level={sql_config['level']}",
                    f"--risk={sql_config['risk']}",
                    f"--technique={sql_config['technique']}"
                ]
                
                if sql_config['tamper']:
                    cmd.append(f"--tamper={sql_config['tamper']}")
                
                if sql_config.get('randomAgent'):
                    cmd.append("--random-agent")
                    
                if sql_config.get('hpp'):
                    cmd.append("--hpp")
                    
                if sql_config.get('hex'):
                    cmd.append("--hex")
                
                print(f"[*] Ejecutando: {' '.join(cmd)}")
                
                # Ejecutar SQLMap y streamear salida
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                    universal_newlines=True, bufsize=1
                )
                
                for line in process.stdout:
                    # Enviar log al C2
                    await websocket.send(json.dumps({
                        'type': 'log',
                        'component': 'CERBERUS_PRO',
                        'level': 'INFO', 
                        'msg': line.strip()
                    }))
                    
if __name__ == "__main__":
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        print("[!] Agente detenido.")
`;
