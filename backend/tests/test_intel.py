
import unittest
import asyncio
import os
import shutil
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
        # This uses the mocked data in fetch_latest_cves
        cves = await self.ingester.fetch_latest_cves(min_score=9.0)
        
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].cve_id, "CVE-2026-0001")
        
        # Check cache
        self.assertTrue(os.path.exists(os.path.join(self.test_cache, "CVE-2026-0001.json")))

    async def test_tech_stack_match(self):
        # Populate cache first
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
