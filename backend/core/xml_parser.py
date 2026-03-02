import xml.etree.ElementTree as ET
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("cerberus_xml_parser")

class XMLPayloadParser:
    """
    Parser nativo para extraer payloads de la bóveda de SQLMap
    sin depender de su extensa y lenta librería heredada.
    """
    
    def __init__(self, xml_dir: str = "backend/core/xml/payloads"):
        self.xml_dir = xml_dir
        
    def _parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        payloads = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for test in root.findall('test'):
                payload_data = {
                    "title": test.findtext("title"),
                    "stype": int(test.findtext("stype", "1")),
                    "level": int(test.findtext("level", "1")),
                    "risk": int(test.findtext("risk", "1")),
                    "clause": test.findtext("clause"),
                    "where": test.findtext("where"),
                    "vector": test.findtext("vector"),
                }
                
                req = test.find("request")
                if req is not None:
                    payload_data["payload"] = req.findtext("payload")
                    payload_data["comment"] = req.findtext("comment")
                    
                resp = test.find("response")
                if resp is not None:
                    payload_data["comparison"] = resp.findtext("comparison")
                    payload_data["grep"] = resp.findtext("grep")
                    payload_data["time"] = resp.findtext("time")
                    
                details = test.find("details")
                if details is not None:
                    payload_data["dbms"] = details.findtext("dbms")
                    
                payloads.append(payload_data)
        except Exception as e:
            logger.error(f"Error parsing XML {file_path}: {e}")
            
        return payloads

    def load_all_payloads(self) -> Dict[str, List[Dict[str, Any]]]:
        """Carga todos los payloads en memoria clasificados por tipo."""
        database = {}
        if not os.path.exists(self.xml_dir):
            logger.warning(f"Carga cancelada: Directorio XML no encontrado en: {self.xml_dir}")
            return database
            
        for filename in os.listdir(self.xml_dir):
            if filename.endswith(".xml"):
                path = os.path.join(self.xml_dir, filename)
                category = filename.replace(".xml", "")
                database[category] = self._parse_file(path)
                logger.debug(f"Loaded {len(database[category])} payloads from {filename}")
                
        return database

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # Testing local execution
    parser = XMLPayloadParser()
    db = parser.load_all_payloads()
    print("\n[+] Resumen de Base de Datos Nativa Cargada:")
    for cat, payloads in db.items():
        print(f" - Categoría: {cat} -> {len(payloads)} vectores")
