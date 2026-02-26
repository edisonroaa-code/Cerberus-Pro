"""
Governance & Policy Engine - Sprint 4.2

Enforces rules of engagement (RoE) to ensure operations remain within scope and authorized windows.
"""
import logging
import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("cerberus.governance.policy")

class ActionType(str, Enum):
    SCAN = "scan"
    EXPLOIT = "exploit"
    EXFILTRATE = "exfiltrate"
    LATERAL_MOVE = "lateral_movement"

@dataclass
class EngagementRules:
    name: str = "Default RoE"
    allowed_subnets: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    authorized_hours_start: int = 0  # 00:00
    authorized_hours_end: int = 24   # 24:00 (All day)
    max_bandwidth_mbps: int = 10
    require_approval_for_exploitation: bool = False

class PolicyEngine:
    """Enforces Rules of Engagement."""
    
    def __init__(self, rules: Optional[EngagementRules] = None):
        self.rules = rules or EngagementRules()
        self._violations: List[Dict] = []

    def load_rules(self, rules: EngagementRules):
        self.rules = rules
        logger.info(f"Policy Engine loaded rules: {rules.name}")

    def check_authorization(self, action: ActionType, target: str) -> bool:
        """
        Check if an action against a target is authorized.
        """
        # 1. Check Time Window
        current_hour = datetime.datetime.now(datetime.timezone.utc).hour
        if not (self.rules.authorized_hours_start <= current_hour < self.rules.authorized_hours_end):
            self._log_violation(action, target, "Outside authorized hours")
            return False

        # 2. Check Excluded Hosts
        if target in self.rules.excluded_hosts:
            self._log_violation(action, target, "Target is explicitly excluded")
            return False

        # 3. Check Action Specifics
        if action == ActionType.EXPLOIT and self.rules.require_approval_for_exploitation:
            # In a real system, check approval workflow status
            self._log_violation(action, target, "Exploitation requires explicit approval")
            return False

        return True

    def _log_violation(self, action: ActionType, target: str, reason: str):
        violation = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "reason": reason
        }
        self._violations.append(violation)
        logger.warning(f"POLICY VIOLATION: {action} against {target} BLOCKED. Reason: {reason}")

    def get_violations(self) -> List[Dict]:
        return self._violations

# Singleton instance
_engine = PolicyEngine()

def get_policy_engine() -> PolicyEngine:
    return _engine
