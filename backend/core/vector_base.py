import abc
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class BaseVector(abc.ABC):
    """
    Clase base abstracta para los micro-motores de inyección (Vectores Ligeros).
    """
    def __init__(self, client: Any, target_url: str):
        self.client = client
        self.target_url = target_url
        self._parsed = urlparse(target_url)
        self._has_params = bool(self._parsed.query)

    def inject_url(self, payload: str) -> str:
        """Construye la URL de inyección de forma inteligente.

        - Si la URL tiene parámetros (?id=1), inyecta en el PRIMER parámetro.
        - Si NO tiene parámetros, inyecta en el PATH (último segmento).
        - Nunca doble-codifica; el payload ya viene mutado por PayloadEvader.
        """
        if self._has_params:
            # Inject into the first query parameter value
            params = parse_qs(self._parsed.query, keep_blank_values=True)
            if params:
                first_key = list(params.keys())[0]
                original_val = params[first_key][0] if params[first_key] else ""
                params[first_key] = [original_val + payload]
                new_query = urlencode(params, doseq=True)
                return urlunparse(self._parsed._replace(query=new_query))
        # Si NO tiene parámetros, creamos un parámetro genérico (?id=) para inyectar.
        # Esto evita romper el enrutamiento (404) de URLs limpias como /tienda
        sep = "&" if "?" in self.target_url else "?"
        return f"{self.target_url}{sep}id=1{payload}"

    @abc.abstractmethod
    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta la estrategia específica del vector contra el objetivo.
        Debe retornar un diccionario con los resultados (Ej. {"status": "vulnerable", ...})
        """
        pass
