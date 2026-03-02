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
import httpx

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

        rows: List[Dict[str, Any]] = []
        try:
            rows = await self._fetch_nvd(limit=limit)
        except Exception as e:
            logger.warning(f"NVD fetch failed, falling back to cached intel feed: {e}")
            rows = self._load_cached_rows()

        results = []
        for item in rows:
            score = float(item.get("cvss_score", 0.0) or 0.0)
            if score >= min_score:
                cve = CVE(
                    cve_id=item.get("cve_id", "UNKNOWN"),
                    description=item.get("description", ""),
                    cvss_score=score,
                    published_date=item.get("published_date", datetime.now(timezone.utc).isoformat()),
                    references=item.get("references", []),
                    affected_products=item.get("affected_products", []),
                )
                results.append(cve)
                self._cache_cve(cve)

        return results

    async def _fetch_nvd(self, limit: int) -> List[Dict[str, Any]]:
        params = {
            "resultsPerPage": max(1, min(int(limit), 2000)),
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(self.nvd_api_url, params=params)
            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        rows: List[Dict[str, Any]] = []
        for item in vulnerabilities:
            cve_obj = (item or {}).get("cve", {})
            cve_id = cve_obj.get("id")
            if not cve_id:
                continue

            descriptions = cve_obj.get("descriptions", []) or []
            description = ""
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and descriptions:
                description = (descriptions[0] or {}).get("value", "")

            refs = []
            for r in cve_obj.get("references", []) or []:
                url = (r or {}).get("url")
                if isinstance(url, str) and url:
                    refs.append(url)

            products = self._extract_products(cve_obj.get("configurations", []) or [])
            score = self._extract_cvss_score(cve_obj.get("metrics", {}) or {})

            rows.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": score,
                    "published_date": cve_obj.get("published", datetime.now(timezone.utc).isoformat()),
                    "references": refs,
                    "affected_products": products,
                }
            )
        return rows

    @staticmethod
    def _extract_cvss_score(metrics: Dict[str, Any]) -> float:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key)
            if not isinstance(metric_list, list) or not metric_list:
                continue
            first = metric_list[0] or {}
            cvss_data = first.get("cvssData", {}) or {}
            score = cvss_data.get("baseScore")
            try:
                return float(score)
            except Exception:
                continue
        return 0.0

    @staticmethod
    def _extract_products(configurations: List[Dict[str, Any]]) -> List[str]:
        products: List[str] = []

        def _walk(nodes: List[Dict[str, Any]]) -> None:
            for node in nodes:
                for match in node.get("cpeMatch", []) or []:
                    criteria = (match or {}).get("criteria", "")
                    if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
                        parts = criteria.split(":")
                        if len(parts) > 4 and parts[4] and parts[4] != "*":
                            products.append(parts[4])
                children = node.get("nodes", []) or []
                if children:
                    _walk(children)

        for conf in configurations:
            nodes = (conf or {}).get("nodes", []) or []
            _walk(nodes)

        # Preserve order while deduplicating.
        seen = set()
        unique = []
        for p in products:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    def _load_cached_rows(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        try:
            for fn in os.listdir(self.cache_dir):
                if not fn.endswith(".json"):
                    continue
                with open(os.path.join(self.cache_dir, fn), "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and data.get("cve_id"):
                    rows.append(data)
        except Exception as e:
            logger.warning(f"Failed to load cached CVE rows: {e}")
        return rows

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

