#!/usr/bin/env python3
"""
Integrated demo: Simulates SQLMap safe runner behavior with:
- Dynamic jitter generation per vector
- UA family rotation on WAF block detection
- Cookie persistence tracking
- Simulated extraction attempts with OOB preference

This script demonstrates without requiring actual sqlmap binary.
"""

import sys
import asyncio
import random
import time
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional

sys.path.insert(0, '.')
from backend.v4_omni_surface import PolymorphicEvasionEngine, UA_POOL


class SimulatedExecutionTracker:
    """Track execution with detailed logging of key events."""
    
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.events = []
        self.ua_history = []
        self.jitter_history = []
        self.cookie_state = None
        self.extraction_results = {}
        self.waf_blocks = []
    
    def log(self, event_type: str, message: str, details: Dict = None):
        """Log an event with timestamp."""
        elapsed = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_sec": round(elapsed, 2),
            "type": event_type,
            "message": message,
            "details": details or {},
        }
        self.events.append(entry)
        
        # Print with color-coded prefix
        prefix = {
            "jitter": "  [JITTER ]",
            "ua_rotate": " [UA-TURN ]",
            "cookie": "  [COOKIE ]",
            "extraction": "[EXTRACT ]",
            "waf_block": " [WAF-BLK ]",
            "phase": "  [PHASE  ]",
        }.get(event_type, "  [EVENT  ]")
        
        print(f"{prefix} {message}")
    
    def log_jitter(self, prev_delay: float, new_delay: float, vector: str):
        """Track jitter changes."""
        delta = new_delay - prev_delay
        message = f"Δ{delta:+.3f}s (was {prev_delay:.3f}s, now {new_delay:.3f}s) for {vector}"
        self.log("jitter", message, {"prev": prev_delay, "new": new_delay, "delta": delta, "vector": vector})
        self.jitter_history.append({"prev": prev_delay, "new": new_delay, "vector": vector})
    
    def log_ua_rotation(self, prev_ua: str, new_ua: str, reason: str = ""):
        """Track UA family changes."""
        prev_fam = self._ua_family(prev_ua)
        new_fam = self._ua_family(new_ua)
        suffix = f" ({reason})" if reason else ""
        message = f"{prev_fam} → {new_fam}{suffix}"
        self.log("ua_rotate", message, {"prev_family": prev_fam, "new_family": new_fam, "reason": reason})
        self.ua_history.append({"prev": prev_fam, "new": new_fam})
    
    def log_cookie_persistence(self, cookie: str, persisted_across: str = ""):
        """Track cookie state."""
        self.cookie_state = {"value": cookie, "persisted_across": persisted_across}
        suffix = f" (persisted across {persisted_across})" if persisted_across else " (obtained)"
        message = f"{'✓' if cookie else '✗'} Cookie {len(cookie) if cookie else 0} bytes{suffix}"
        self.log("cookie", message, {"cookie_len": len(cookie) if cookie else 0, "persisted_across": persisted_across})
    
    def log_extraction_attempt(self, query_type: str, success: bool, evidence: str = ""):
        """Track extraction attempts."""
        status = "✓" if success else "✗"
        message = f"{status} {query_type}: {evidence[:80]}" if evidence else f"{status} {query_type}"
        self.log("extraction", message, {"query": query_type, "success": success, "evidence": evidence[:100]})
        self.extraction_results[query_type] = {"success": success, "evidence": evidence}
    
    def log_waf_block(self, http_code: int, vector: str, ua: str):
        """Track WAF blocks."""
        ua_fam = self._ua_family(ua)
        message = f"HTTP {http_code} on {vector} with {ua_fam}"
        self.log("waf_block", message, {"http_code": http_code, "vector": vector, "ua_family": ua_fam})
        self.waf_blocks.append({"code": http_code, "vector": vector, "ua_family": ua_fam})
    
    def log_phase(self, phase_name: str, status: str = "started"):
        """Log phase progress."""
        message = f"{phase_name.upper()} {status}"
        self.log("phase", message, {"phase": phase_name, "status": status})
    
    @staticmethod
    def _ua_family(ua: str) -> str:
        """Extract UA family from user agent string."""
        u = str(ua or "").lower()
        if "firefox" in u:
            return "Firefox"
        elif "chrome" in u:
            return "Chrome"
        elif "edge" in u:
            return "Edge"
        elif "safari" in u:
            return "Safari"
        return "Other"
    
    def save_report(self, path: str):
        """Save detailed report to JSON."""
        report = {
            "execution_time_sec": (datetime.now(timezone.utc) - self.start_time).total_seconds(),
            "total_events": len(self.events),
            "jitter_changes": len(self.jitter_history),
            "ua_rotations": len(self.ua_history),
            "waf_blocks": len(self.waf_blocks),
            "extraction_attempts": len(self.extraction_results),
            "successful_extractions": sum(1 for r in self.extraction_results.values() if r["success"]),
            "jitter_history": self.jitter_history,
            "ua_history": self.ua_history,
            "waf_blocks_detail": self.waf_blocks,
            "extraction_results": self.extraction_results,
            "cookie_state": self.cookie_state,
            "all_events": self.events[-50:],  # Last 50 events
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[REPORT] Detailed log saved to {path}")


async def simulate_integrated_flow():
    """
    Simulate the full flow:
    1. Initial scan with jitter detection
    2. WAF block detected → UA rotation
    3. Cookie persistence across rotation
    4. Extraction attempts with OOB preference
    """
    
    print("=" * 90)
    print("SIMULATION: SQLMap Safe Runner with Advanced Evasion & Extraction")
    print("=" * 90)
    print()
    
    tracker = SimulatedExecutionTracker()
    polymorphic = PolymorphicEvasionEngine(waf_type="cloudflare")
    
    # Phase 1: Initial vulnerability scan
    tracker.log_phase("Phase 1: Initial vulnerability detection")
    
    vectors = ["UNION", "ERROR", "TIME"]
    prev_jitter = 0.05
    current_ua = random.choice(UA_POOL)
    
    for idx, vector in enumerate(vectors[:2]):  # Probe first 2 vectors
        # Simulate dynamic jitter per vector
        new_jitter = polymorphic.traffic_jitter(base_delay=0.05)
        if new_jitter != prev_jitter:
            tracker.log_jitter(prev_jitter, new_jitter, vector)
            prev_jitter = new_jitter
        
        print(f"    {vector}: delay={new_jitter:.3f}s | UA={SimulatedExecutionTracker._ua_family(current_ua)}")
        await asyncio.sleep(0.1)  # Simulate request
    
    tracker.log_phase("Phase 1", "completed")
    print()
    
    # Phase 2: WAF detection and adaptation
    tracker.log_phase("Phase 2: WAF block detection & response")
    print("    → Simulating 502 Bad Gateway response after payload injection...")
    
    tracker.log_waf_block(502, "ERROR", current_ua)
    await asyncio.sleep(0.2)
    
    # Rotate UA on WAF block
    print("    → Triggering UA family rotation...")
    new_ua = random.choice([u for u in UA_POOL if "firefox" in u.lower()])
    tracker.log_ua_rotation(current_ua, new_ua, reason="waf_active_blocking/502")
    current_ua = new_ua
    
    # Force new jitter after rotation
    new_jitter = polymorphic.traffic_jitter(base_delay=0.15)
    tracker.log_jitter(prev_jitter, new_jitter, "post-rotation")
    prev_jitter = new_jitter
    
    tracker.log_phase("Phase 2", "completed - adapted to WAF")
    print()
    
    # Phase 3: Cookie persistence and resumption
    tracker.log_phase("Phase 3: Playwright bypass & session persistence")
    print("    → Simulating Playwright bypass of JavaScript challenge...")
    
    mock_cookie = "cf_clearance=abc123def456x789y; session_id=deadbeef"
    await asyncio.sleep(0.3)  # Simulate browser automation
    tracker.log_cookie_persistence(mock_cookie, persisted_across="initial_bypass")
    
    print("    → Resuming scan with obtained credentials...")
    print(f"    → Cookie persisted after UA rotation: {SimulatedExecutionTracker._ua_family(current_ua)}")
    tracker.log_cookie_persistence(mock_cookie, persisted_across="ua_rotation")
    
    tracker.log_phase("Phase 3", "completed - session active")
    print()
    
    # Phase 4: Targeted extraction
    tracker.log_phase("Phase 4: Data extraction (OOB priority)")
    print("    → Attempting --current-db extraction using initial positive vector (ERROR)...")
    
    # Prefer OOB/DNS if available
    use_dns_oob = True
    if use_dns_oob:
        print("    → OOB DNS channel available, attempting extraction via DNS tunnel...")
        tracker.log_extraction_attempt("current_db_via_oob", True, "remote_dbms_name=production_db")
    else:
        print("    → Direct HTTP extraction with persistent cookie...")
        tracker.log_extraction_attempt("current_db_http", True, "current database: webapp_db")
    
    tracker.log_extraction_attempt("current_user", True, "current user: www-data@localhost")
    tracker.log_extraction_attempt("database_list", True, "mysql, information_schema, performance_schema, webapp_db")
    
    tracker.log_phase("Phase 4", "completed - data extracted")
    print()
    
    # Final report
    print("=" * 90)
    print("EXECUTION SUMMARY")
    print("=" * 90)
    print(f"  Total execution time: {(datetime.now(timezone.utc) - tracker.start_time).total_seconds():.2f}s")
    print(f"  Jitter changes:       {len(tracker.jitter_history)} (dynamic per-vector timing)")
    print(f"  UA rotations:         {len(tracker.ua_history)} (family changes on WAF block)")
    print(f"  Cookie events:        2 (initial bypass + persistence across UA rotation)")
    print(f"  WAF blocks detected:  {len(tracker.waf_blocks)}")
    print(f"  Extractions:          {sum(1 for r in tracker.extraction_results.values() if r['success'])}/{len(tracker.extraction_results)} successful")
    print()
    print("DETAILED FINDINGS:")
    for query_type, result in tracker.extraction_results.items():
        status = "✓" if result["success"] else "✗"
        print(f"  {status} {query_type}: {result['evidence'][:70]}")
    print()
    print("KEY OBSERVATIONS:")
    print("  1. Jitter is recalculated per vector (not static 0.76s)")
    print("  2. UA family changed from Chrome to Firefox after 502 block")
    print("  3. Cookies persisted across UA rotation without loss")
    print("  4. Extraction attempted via OOB DNS (preferred method)")
    print("  5. Current DB extracted successfully after rotation")
    print("=" * 90)
    
    # Save detailed log
    tracker.save_report("backend/demo_integrated_execution_log.json")


if __name__ == "__main__":
    print()
    asyncio.run(simulate_integrated_flow())
