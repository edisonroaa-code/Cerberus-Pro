import asyncio
import os
import time
from dotenv import load_dotenv
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_threat_intel")

from backend.offensiva.proxy_rotator import ProxyRotator

async def run_test():
    load_dotenv()
    print("🚀 Iniciando prueba de Ciberinteligencia Activa (P5-D)...")
    
    rotator = ProxyRotator()
    
    # Nodo 1: Proxy Público saturado (Benigno pero lento)
    pub_url = "http://192.168.1.10:8080"
    rotator.add_proxy(pub_url)
    
    # Nodo 2: Honeypot / Tarpit (Latencia perfecta, 100% bloques)
    honey_url = "socks5://evil-tarpit.blue.team:9050"
    rotator.add_proxy(honey_url)
    
    # Simulando telemetría
    print("\n📡 Simulando tráfico de red para recolectar telemetría...")
    
    # Telemetría Pública (latencia ruidosa, fallos orgánicos)
    rotator.record_telemetry(pub_url, latency_ms=120, was_blocked=False)
    rotator.record_telemetry(pub_url, latency_ms=450, was_blocked=True)
    rotator.record_telemetry(pub_url, latency_ms=135, was_blocked=False)
    rotator.record_telemetry(pub_url, latency_ms=800, was_blocked=False)

    # Telemetría Honeypot (latencia artificial plana, alto bloqueo)
    rotator.record_telemetry(honey_url, latency_ms=50, was_blocked=True)
    rotator.record_telemetry(honey_url, latency_ms=51, was_blocked=True)
    rotator.record_telemetry(honey_url, latency_ms=50, was_blocked=True)
    rotator.record_telemetry(honey_url, latency_ms=49, was_blocked=True)
    
    # Ajustando reloj para bypass de límite de evaluación de 30seg
    for p in rotator.pool:
        p.last_evaluation_time = time.time() - 60
    
    print("\n🧠 Invocando a Cortex AI para evaluar los proxies...")
    await rotator.evaluate_fleet_safety()
    
    print("\n📊 Estado Final del Router de Proxies:")
    for p in rotator.pool:
        status = "🔴 QUEMADO (Honeypot)" if p.is_burned else ("🟢 ACTIVO" if p.intel_score >= 0.5 else "🟡 SOSPECHOSO")
        print(f"[{status}] {p.url} -> Confianza IA: {p.intel_score:.2f}")

if __name__ == "__main__":
    asyncio.run(run_test())
