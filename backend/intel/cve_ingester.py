"""
CVE Ingester Module - Sprint 4.1

Ingests and processes CVE feeds (NVD, GitHub) to identify relevant threats.
"""
import asyncio
import logging
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger("cerberus.intel.cve")

@dataclass
class CVE:
    cve_id: str
    description: str
    cvss_score: float
    published_date: str
    references: List[str]
    affected_products: List[str]

class CVEIngester:
    """Ingests vulnerability data from external sources."""

    def __init__(self, cache_dir: str = ".cache/intel"):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def fetch_latest_cves(self, limit: int = 50, min_score: float = 7.0) -> List[CVE]:
        """Fetch latest high-severity CVEs."""
        logger.info(f"Fetching latest CVEs (min_cvss={min_score})...")
        
        # In a real implementation, we would call NVD API with aiohttp
        # async with aiohttp.ClientSession() as session:
        #    ...
        
        # Simulating API response for "offline" development
        mock_data = [
            {
                "cve_id": "CVE-2026-0001",
                "description": "Critical SQL Injection in GenericCMS v4.0 allows unauthenticated RCE.",
                "cvss_score": 9.8,
                "published_date": datetime.now(timezone.utc).isoformat(),
                "references": ["https://github.com/advisories/GHSA-1234"],
                "affected_products": ["GenericCMS"]
            },
            {
                "cve_id": "CVE-2026-0002",
                "description": "Buffer Overflow in OldServer allows DoS.",
                "cvss_score": 7.5,
                "published_date": datetime.now(timezone.utc).isoformat(),
                "references": [],
                "affected_products": ["OldServer"]
            }
        ]
        
        results = []
        for item in mock_data:
            if item["cvss_score"] >= min_score:
                cve = CVE(
                    cve_id=item["cve_id"],
                    description=item["description"],
                    cvss_score=item["cvss_score"],
                    published_date=item["published_date"],
                    references=item["references"],
                    affected_products=item["affected_products"]
                )
                results.append(cve)
                self._cache_cve(cve)
        
        return results

    def _cache_cve(self, cve: CVE):
        """Cache CVE to disk."""
        path = os.path.join(self.cache_dir, f"{cve.cve_id}.json")
        try:
            with open(path, "w") as f:
                json.dump(cve.__dict__, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to cache CVE {cve.cve_id}: {e}")

    async def check_cve_match(self, tech_stack: List[str]) -> List[CVE]:
        """Check if any cached CVEs match the target tech stack."""
        matches = []
        # Naive scan of cache directory
        if not os.path.exists(self.cache_dir):
            return []
            
        for fn in os.listdir(self.cache_dir):
            if fn.endswith(".json"):
                try:
                    with open(os.path.join(self.cache_dir, fn), "r") as f:
                        data = json.load(f)
                        cve = CVE(**data)
                        
                        # Check logic
                        for product in cve.affected_products:
                            for tech in tech_stack:
                                if tech.lower() in product.lower() or product.lower() in tech.lower():
                                    matches.append(cve)
                                    break
                except Exception:
                    continue
        return matches

# Test runner
if __name__ == "__main__":
    async def main():
        ingester = CVEIngester()
        cves = await ingester.fetch_latest_cves()
        print(f"Ingested {len(cves)} CVEs")
        
        matches = await ingester.check_cve_match(["GenericCMS", "Nginx"])
        print(f"Found {len(matches)} matches for stack")
        
    asyncio.run(main())

