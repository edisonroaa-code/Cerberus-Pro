import os
import json
from datetime import datetime

class EvidenceStorage:
    """Stores attack evidence and HAR logs for forensic audit."""
    
    def __init__(self, storage_dir: str = "backend/evidence"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def save_har(self, scan_id: str, har_data: Dict) -> str:
        """Saves a HAR log for the given scan."""
        path = os.path.join(self.storage_dir, f"evidence_{scan_id}.har")
        with open(path, "w") as f:
            json.dump(har_data, f)
        return path

    def save_screenshot(self, scan_id: str, image_bytes: bytes) -> str:
        """Saves a screenshot captured during Playwright evasion."""
        path = os.path.join(self.storage_dir, f"capture_{scan_id}.png")
        with open(path, "wb") as f:
            f.write(image_bytes)
        return path
