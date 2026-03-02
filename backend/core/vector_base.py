import abc
from typing import Dict, Any

class BaseVector(abc.ABC):
    """
    Clase base abstracta para los micro-motores de inyección (Vectores Ligeros).
    """
    def __init__(self, client: Any, target_url: str):
        self.client = client
        self.target_url = target_url

    @abc.abstractmethod
    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta la estrategia específica del vector contra el objetivo.
        Debe retornar un diccionario con los resultados (Ej. {"status": "vulnerable", ...})
        """
        pass
