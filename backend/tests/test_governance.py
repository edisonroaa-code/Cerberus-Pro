
import unittest
import datetime
from unittest.mock import patch, MagicMock
from backend.governance.policy_engine import PolicyEngine, EngagementRules, ActionType

class TestGovernance(unittest.TestCase):
    
    def test_default_rules(self):
        engine = PolicyEngine()
        # Default rules allow mostly everything except maybe exclusions
        self.assertTrue(engine.check_authorization(ActionType.SCAN, "192.168.1.1"))

    def test_excluded_host(self):
        rules = EngagementRules(excluded_hosts=["10.0.0.1"])
        engine = PolicyEngine(rules)
        
        self.assertFalse(engine.check_authorization(ActionType.SCAN, "10.0.0.1"))
        self.assertTrue(engine.check_authorization(ActionType.SCAN, "10.0.0.2"))
        
        violations = engine.get_violations()
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["target"], "10.0.0.1")

    def test_time_window_block(self):
        # Allow only 00:00 - 01:00. Assuming test runs after 01:00 or modify datetime
        current_hour = datetime.datetime.now().hour
        start = (current_hour + 1) % 24
        end = (current_hour + 2) % 24
        
        if start > end: # wrap around case (e.g. 23:00 to 00:00)
             # simpler: make a window that definitely excludes now
             start = (current_hour + 2) % 24
             end = (current_hour + 3) % 24

        rules = EngagementRules(
            authorized_hours_start=start,
            authorized_hours_end=end
        )
        engine = PolicyEngine(rules)
        
        self.assertFalse(engine.check_authorization(ActionType.EXPLOIT, "target.com"))
        
    def test_exploitation_approval(self):
        rules = EngagementRules(require_approval_for_exploitation=True)
        engine = PolicyEngine(rules)
        
        self.assertFalse(engine.check_authorization(ActionType.EXPLOIT, "target.com"))
        self.assertTrue(engine.check_authorization(ActionType.SCAN, "target.com"))

if __name__ == '__main__':
    unittest.main()
