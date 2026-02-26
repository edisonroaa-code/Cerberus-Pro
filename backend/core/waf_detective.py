"""
WAF Detective - fingerprinting and basic detection heuristics
"""
import asyncio
import logging
from typing import Optional, Dict, Any
from urllib.parse import urljoin

try:
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        import aiohttp
    else:
        import aiohttp
except Exception:
    aiohttp = None

logger = logging.getLogger("cerberus.core.waf_detective")


async def fingerprint(target: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Attempt to fingerprint common WAFs.

    Returns a dict with keys: {"waf": name or None, "evidence": str}
    """
    if not aiohttp:
        logger.debug("aiohttp not available, cannot perform WAF fingerprinting")
        return None

    probes = ["/", "/%3Cscript%3Ealert(1)%3C/script%3E", "/admin/login"]
    headers = {"User-Agent": "Cerberus-WAF-Detect/1.0"}

    async with aiohttp.ClientSession() as session:
        for probe in probes:
            url = target.rstrip("/") + probe
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True, ssl=False) as resp:
                    text = await resp.text()
                    # Check headers
                    server = resp.headers.get("Server", "").lower()
                    via = resp.headers.get("Via", "").lower()
                    set_cookie = resp.headers.get("Set-Cookie", "").lower()

                    # Heuristics for known WAFs
                    if "cloudflare" in server or "__cf_" in set_cookie:
                        return {"waf": "Cloudflare", "evidence": f"Server:{server} Cookies:{set_cookie}"}
                    if "akamai" in server or "akamaized" in via:
                        return {"waf": "Akamai", "evidence": f"Server:{server} Via:{via}"}
                    if "mod_security" in set_cookie or "mod_security" in server or "mod_security" in text.lower():
                        return {"waf": "ModSecurity", "evidence": "modsecurity signature in response"}
                    if resp.status in (403, 406, 415):
                        # Could be WAF blocking
                        # Try to fingerprint based on body
                        if "request blocked" in text.lower() or "access denied" in text.lower() or "forbidden" in text.lower():
                            return {"waf": "GenericWAF", "evidence": f"status:{resp.status} body_snippet:{text[:200]}"}
            except asyncio.TimeoutError:
                logger.debug(f"WAF probe timeout for {url}")
            except Exception as e:
                logger.debug(f"WAF probe error for {url}: {e}")

    return None
