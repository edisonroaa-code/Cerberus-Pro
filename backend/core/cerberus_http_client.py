import asyncio
import httpx
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("cerberus_http")

class CerberusHTTPClient:
    """
    Cliente HTTP nativo y asíncrono para el Cerberus Engine v5.0.
    Reemplaza totalmente la capa de red del antiguo sqlmap.
    Soporta routing dinámico a través de:
    - Conexión normal
    - TOR (via SOCKS5)
    - Proxies HTTP/SOCKS rotativos
    """
    
    def __init__(self, use_tor: bool = False, tor_port: int = 9050, proxy: Optional[str] = None, timeout: int = 10, random_agent: bool = True):
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.proxy = proxy
        self.timeout = timeout
        self.random_agent = random_agent
        self.client: Optional[httpx.AsyncClient] = None
        self._setup_client()

    def _get_user_agent(self) -> str:
        if self.random_agent:
            # Lista básica rotativa (en el futuro Cortex AI puede sugerir agents específicos para camuflaje)
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CerberusEngine/5.0"
        return "CerberusPro/5.0 Engine"

    def _setup_client(self):
        """Inicializa el cliente HTTPX asíncrono con el enrutamiento correcto."""
        proxy_url = None
        
        if self.use_tor:
            # Enrutamiento fuerte por TOR SOCKS5 (localhost)
            proxy_url = f"socks5://127.0.0.1:{self.tor_port}"
            logger.info(f"[+] Ghost Network ACTIVA: Ruteando por nodo cebolla ({proxy_url})")
        elif self.proxy:
            # Enrutamiento de proxy personalizado
            proxy_url = self.proxy
            logger.info(f"[+] Ghost Proxy Routing: {self.proxy}")

        headers = {
            "User-Agent": self._get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            # Headers útiles para evadir WAFs básicos que marcan peticiones vacías
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        # Transport configuration
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
        
        self.client = httpx.AsyncClient(
            proxy=proxy_url,
            verify=False, # Ignorar certificados SSL inválidos del objetivo
            timeout=httpx.Timeout(self.timeout),
            headers=headers,
            limits=limits,
            follow_redirects=True
        )

    async def get(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, timeout: Optional[float] = None) -> httpx.Response:
        """Fuerza una petición GET al objetivo"""
        req_headers = self.client.headers.copy()
        if headers:
            req_headers.update(headers)
            
        return await self.client.get(url, params=params, headers=req_headers, timeout=timeout)

    async def post(self, url: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, timeout: Optional[float] = None) -> httpx.Response:
        """Fuerza una petición POST al objetivo"""
        req_headers = self.client.headers.copy()
        if headers:
            req_headers.update(headers)
            
        return await self.client.post(url, data=data, json=json, headers=req_headers, timeout=timeout)

    async def close(self):
        """Cierra el pool de conexiones"""
        if self.client:
            await self.client.aclose()
            logger.debug("[-] Conexiones del Cerberus Engine cerradas.")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

# Ejemplo unitario de testing rápido si se ejecuta el módulo directo
if __name__ == "__main__":
    async def _test():
        logging.basicConfig(level=logging.INFO)
        print("Test 1: Normal Client")
        async with CerberusHTTPClient() as engine:
            pass # implement local context manager later if needed
            
        engine = CerberusHTTPClient(timeout=5)
        try:
            resp = await engine.get("https://httpbin.org/ip")
            print("Response Normal:", resp.json())
        except Exception as e:
            print("Error:", e)
        finally:
            await engine.close()

    asyncio.run(_test())
