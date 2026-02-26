import hashlib
import json
import os
from typing import Dict, List, Optional

class IntelligenceService:
    """Advanced analysis: Differential scanning and BOLA/IDOR detection."""
    
    def __init__(self, history_dir: str = "backend/history"):
        self.history_dir = history_dir
        os.makedirs(self.history_dir, exist_ok=True)

    def compute_structure_hash(self, content: str) -> str:
        """Computes a hash of the response structure (ignores dynamic data)."""
        # Simplified: just hash the content for now
        return hashlib.sha256(content.encode()).hexdigest()

    def detect_differential_delta(self, target_url: str, current_hash: str) -> Dict:
        """Compares current scan result with the previous one."""
        target_slug = hashlib.md5(target_url.encode()).hexdigest()
        history_path = os.path.join(self.history_dir, f"{target_slug}.json")
        
        delta = {"changed": False, "previous_hash": None}
        
        if os.path.exists(history_path):
            with open(history_path, "r") as f:
                prev_data = json.load(f)
                delta["previous_hash"] = prev_data.get("hash")
                if delta["previous_hash"] != current_hash:
                    delta["changed"] = True
        
        # Save current for next time
        with open(history_path, "w") as f:
            json.dump({"url": target_url, "hash": current_hash}, f)
            
        return delta

    def probe_bola_idor(self, base_url: str, resource_id: str) -> List[str]:
        """Simple baseline probe for IDOR/BOLA (e.g. incrementing IDs)."""
        findings = []
        if resource_id.isdigit():
            # In a real implementation, we would probe concurrent IDs
            findings.append(f"Potential BOLA vulnerability: sequential ID {resource_id} detected.")
        return findings
