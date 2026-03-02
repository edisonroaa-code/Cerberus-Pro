
import unittest
import asyncio
import os
import shutil
from unittest.mock import AsyncMock, patch
from backend.intel.cve_ingester import CVEIngester, CVE

class TestIntel(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.test_cache = ".cache/test_intel"
        os.makedirs(self.test_cache, exist_ok=True)
        self.ingester = CVEIngester(cache_dir=self.test_cache)

    def tearDown(self):
        if os.path.exists(self.test_cache):
            shutil.rmtree(self.test_cache)

    async def test_fetch_and_cache(self):
        sample_rows = [
            {
                "cve_id": "CVE-2026-0001",
                "description": "Critical SQL Injection in GenericCMS v4.0 allows unauthenticated RCE.",
                "cvss_score": 9.8,
                "published_date": "2026-01-01T00:00:00+00:00",
                "references": ["https://github.com/advisories/GHSA-1234"],
                "affected_products": ["GenericCMS"],
            },
            {
                "cve_id": "CVE-2026-0002",
                "description": "Buffer Overflow in OldServer allows DoS.",
                "cvss_score": 7.5,
                "published_date": "2026-01-02T00:00:00+00:00",
                "references": [],
                "affected_products": ["OldServer"],
            },
        ]
        with patch.object(self.ingester, "_fetch_nvd", new=AsyncMock(return_value=sample_rows)):
            cves = await self.ingester.fetch_latest_cves(min_score=9.0)
        
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].cve_id, "CVE-2026-0001")
        
        # Check cache
        self.assertTrue(os.path.exists(os.path.join(self.test_cache, "CVE-2026-0001.json")))

    async def test_tech_stack_match(self):
        sample_rows = [
            {
                "cve_id": "CVE-2026-0001",
                "description": "Critical SQL Injection in GenericCMS v4.0 allows unauthenticated RCE.",
                "cvss_score": 9.8,
                "published_date": "2026-01-01T00:00:00+00:00",
                "references": ["https://github.com/advisories/GHSA-1234"],
                "affected_products": ["GenericCMS"],
            },
            {
                "cve_id": "CVE-2026-0002",
                "description": "Buffer Overflow in OldServer allows DoS.",
                "cvss_score": 7.5,
                "published_date": "2026-01-02T00:00:00+00:00",
                "references": [],
                "affected_products": ["OldServer"],
            },
        ]
        with patch.object(self.ingester, "_fetch_nvd", new=AsyncMock(return_value=sample_rows)):
            await self.ingester.fetch_latest_cves(min_score=5.0)
        
        # Test match
        matches = await self.ingester.check_cve_match(["GenericCMS"])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].affected_products[0], "GenericCMS")
        
        # Test no match
        matches_none = await self.ingester.check_cve_match(["Apache"])
        self.assertEqual(len(matches_none), 0)

if __name__ == '__main__':
    unittest.main()
