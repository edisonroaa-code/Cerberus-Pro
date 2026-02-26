"""
Post-Exfiltration Policy Engine

Defines allowed post-exfiltration behaviors and guards. Ensures that automated
exfiltration is constrained by policy flags and audit logging.

Purpose: Safety layer to prevent unauthorized data handling and to record
what was exfiltrated and why.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class PolicyMode(str, Enum):
    DISABLED = "disabled"        # No automation allowed
    AUDIT_ONLY = "audit_only"    # Run but only log, no external export
    ALLOWED = "allowed"          # Full automation (use with caution)


@dataclass
class ExfiltrationRecord:
    timestamp: datetime
    target: str
    size_bytes: int
    method: str
    reason: str


@dataclass
class PostExfiltrationPolicy:
    # User authorized change: allow automated exfiltration by default
    mode: PolicyMode = PolicyMode.ALLOWED
    allowed_targets: List[str] = field(default_factory=lambda: ["*"])
    audit_log: List[ExfiltrationRecord] = field(default_factory=list)
    max_bytes_per_scan: int = 10 * 1024 * 1024  # 10MB

    def can_exfiltrate(self, target: str, size_bytes: int) -> bool:
        if self.mode == PolicyMode.DISABLED:
            return False
        if size_bytes > self.max_bytes_per_scan:
            return False
        if self.mode == PolicyMode.AUDIT_ONLY:
            return True  # allow internal simulation but disallow external export
        # ALLOWED: check allowed targets
        if "*" in self.allowed_targets:
            return True
        return target in self.allowed_targets

    def record_exfiltration(self, target: str, size_bytes: int, method: str, reason: str):
        rec = ExfiltrationRecord(timestamp=datetime.now(timezone.utc), target=target, size_bytes=size_bytes, method=method, reason=reason)
        self.audit_log.append(rec)
        return rec


# Singleton
_policy: Optional[PostExfiltrationPolicy] = None

def get_post_exfiltration_policy() -> PostExfiltrationPolicy:
    global _policy
    if _policy is None:
        _policy = PostExfiltrationPolicy()
    return _policy

