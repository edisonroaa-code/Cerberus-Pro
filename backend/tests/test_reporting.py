
import unittest
from backend.reporting.red_team_report import RedTeamReporter, ReportFinding

class TestReporting(unittest.TestCase):
    
    def test_report_generation(self):
        reporter = RedTeamReporter(client_name="TestCorp")
        
        finding = ReportFinding(
            title="SQL Injection",
            severity="Critical",
            description="Found blind SQLi in id parameter.",
            evidence="sqlmap output...",
            remediation="Use prepared statements."
        )
        reporter.add_finding(finding)
        
        md = reporter.generate_markdown_report()
        
        self.assertIn("# Red Team Engagement Report", md)
        self.assertIn("TestCorp", md)
        self.assertIn("SQL Injection", md)
        self.assertIn("Overall Risk Score:", md)

    def test_risk_score(self):
        reporter = RedTeamReporter()
        # 1 Critical (10) + 1 Medium (4) = 14 / 2 = 7.0
        reporter.add_finding(ReportFinding("Crit", "Critical", "", "", ""))
        reporter.add_finding(ReportFinding("Med", "Medium", "", "", ""))
        
        score = reporter._calculate_risk_score()
        self.assertEqual(score, 7.0)

if __name__ == '__main__':
    unittest.main()
