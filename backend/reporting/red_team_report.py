"""
Red Team Reporting Module - v4.8

Generates comprehensive reports in Markdown, HTML, and JSON formats.
Integrates with EvidenceStore for structured evidence consolidation.
Includes MITRE ATT&CK mapping and CVSS scoring.
"""
import logging
import datetime
import json
import html as html_module
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("cerberus.reporting")

# MITRE ATT&CK mapping for common finding types
MITRE_MAPPING = {
    "sql_injection": {"id": "T1190", "tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "xss": {"id": "T1059.007", "tactic": "Execution", "technique": "JavaScript"},
    "ssti": {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "rce": {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
    "lfi": {"id": "T1005", "tactic": "Collection", "technique": "Data from Local System"},
    "auth_bypass": {"id": "T1556", "tactic": "Persistence", "technique": "Modify Authentication Process"},
    "info_disclosure": {"id": "T1082", "tactic": "Discovery", "technique": "System Information Discovery"},
    "enumeration": {"id": "T1087", "tactic": "Discovery", "technique": "Account Discovery"},
}

CVSS_ESTIMATE = {
    "Critical": 9.8,
    "High": 7.5,
    "Medium": 5.3,
    "Low": 3.1,
}


@dataclass
class ReportFinding:
    title: str
    severity: str  # Critical, High, Medium, Low
    description: str
    evidence: str
    remediation: str
    parameter: str = ""
    url: str = ""
    payload: str = ""
    engine: str = ""
    vuln_type: str = ""
    confidence: float = 0.0
    cvss_score: float = 0.0
    mitre_attack_id: str = ""
    mitre_technique: str = ""
    timestamp: str = ""


class RedTeamReporter:
    """Generates engagement reports in multiple formats."""

    def __init__(self, client_name: str = "Client Corp", target_url: str = ""):
        self.client_name = client_name
        self.target_url = target_url
        self.findings: List[ReportFinding] = []
        self.actions_log: List[Dict] = []
        self.scan_metadata: Dict[str, Any] = {}

    def add_finding(self, finding: ReportFinding):
        # Auto-populate MITRE and CVSS if not set
        if not finding.mitre_attack_id and finding.vuln_type:
            mitre = MITRE_MAPPING.get(finding.vuln_type, {})
            finding.mitre_attack_id = mitre.get("id", "")
            finding.mitre_technique = mitre.get("technique", "")
        if not finding.cvss_score:
            finding.cvss_score = CVSS_ESTIMATE.get(finding.severity, 0.0)
        if not finding.timestamp:
            finding.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.findings.append(finding)

    def add_finding_from_evidence(self, evidence_item) -> ReportFinding:
        """Create a ReportFinding from an EvidenceItem (from evidence_store)."""
        finding = ReportFinding(
            title=f"{evidence_item.vuln_type.value.upper()} in {evidence_item.parameter or evidence_item.vector}",
            severity=evidence_item.severity.value.capitalize(),
            description=f"Vulnerability detected by {evidence_item.engine} engine on parameter '{evidence_item.parameter or evidence_item.vector}'",
            evidence=evidence_item.response_snippet or evidence_item.payload,
            remediation=self._auto_remediation(evidence_item.vuln_type.value),
            parameter=evidence_item.parameter,
            url=evidence_item.url,
            payload=evidence_item.payload,
            engine=evidence_item.engine,
            vuln_type=evidence_item.vuln_type.value,
            confidence=evidence_item.confidence,
        )
        self.add_finding(finding)
        return finding

    def log_action(self, action: str, details: str):
        self.actions_log.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "action": action,
            "details": details,
        })

    def set_metadata(self, **kwargs):
        """Set scan metadata (duration, engines_used, etc.)."""
        self.scan_metadata.update(kwargs)

    # ── Markdown Report ──────────────────────────────────────────────────
    def generate_markdown_report(self) -> str:
        """Generate a full markdown report."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        score = self._calculate_risk_score()

        md = f"# Red Team Engagement Report\n\n"
        md += f"**Client:** {self.client_name}\n"
        md += f"**Target:** {self.target_url}\n"
        md += f"**Date:** {now}\n\n"

        # Executive Summary
        md += "## 1. Executive Summary\n\n"
        md += "Cerberus conducted a simulated adversarial emulation to identify weaknesses in the target infrastructure.\n"
        md += f"A total of **{len(self.findings)}** unique vulnerabilities were identified.\n\n"
        md += f"### Overall Risk Score: {score:.1f}/10\n\n"

        # Severity counts
        sev_counts = self._severity_counts()
        if sev_counts:
            md += "| Severity | Count | Avg CVSS |\n"
            md += "|----------|-------|----------|\n"
            for sev, data in sev_counts.items():
                md += f"| {sev} | {data['count']} | {data['avg_cvss']:.1f} |\n"
            md += "\n"

        # Findings Table
        md += "## 2. Findings Summary\n\n"
        md += "| # | Severity | CVSS | Title | MITRE ATT&CK | Confidence |\n"
        md += "|---|----------|------|-------|--------------|------------|\n"
        for i, f in enumerate(self.findings, 1):
            mitre = f.mitre_attack_id or "—"
            conf = f"{f.confidence:.0%}" if f.confidence else "—"
            md += f"| {i} | {f.severity} | {f.cvss_score:.1f} | {f.title} | {mitre} | {conf} |\n"
        md += "\n"

        # Technical Details
        md += "## 3. Technical Details\n\n"
        for i, f in enumerate(self.findings, 1):
            md += f"### {i}. {f.title} ({f.severity})\n\n"
            md += f"**CVSS Score:** {f.cvss_score:.1f}\n"
            if f.mitre_attack_id:
                md += f"**MITRE ATT&CK:** {f.mitre_attack_id} — {f.mitre_technique}\n"
            if f.url:
                md += f"**URL:** `{f.url}`\n"
            if f.parameter:
                md += f"**Parameter:** `{f.parameter}`\n"
            if f.engine:
                md += f"**Engine:** {f.engine}\n"
            md += f"\n**Description:**\n{f.description}\n\n"
            if f.payload:
                md += f"**Payload:**\n```\n{f.payload}\n```\n\n"
            md += f"**Evidence:**\n```\n{f.evidence}\n```\n\n"
            md += f"**Remediation:**\n{f.remediation}\n\n"
            md += "---\n\n"

        # Action Log
        md += "## 4. Operation Timeline\n\n"
        for log in self.actions_log:
            md += f"- **{log['timestamp']}**: {log['action']} — {log['details']}\n"

        return md

    # ── HTML Report ──────────────────────────────────────────────────────
    def generate_html_report(self) -> str:
        """Generate a styled HTML report with inline CSS."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        score = self._calculate_risk_score()
        esc = html_module.escape

        sev_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#17a2b8",
        }

        findings_html = ""
        for i, f in enumerate(self.findings, 1):
            color = sev_colors.get(f.severity, "#6c757d")
            findings_html += f"""
            <div class="finding">
                <div class="finding-header" style="border-left: 4px solid {color};">
                    <span class="badge" style="background:{color};">{esc(f.severity)}</span>
                    <strong>{i}. {esc(f.title)}</strong>
                    <span class="cvss">CVSS {f.cvss_score:.1f}</span>
                </div>
                <div class="finding-body">
                    <p>{esc(f.description)}</p>
                    {"<p><strong>Parameter:</strong> <code>" + esc(f.parameter) + "</code></p>" if f.parameter else ""}
                    {"<p><strong>MITRE:</strong> " + esc(f.mitre_attack_id) + " — " + esc(f.mitre_technique) + "</p>" if f.mitre_attack_id else ""}
                    {"<pre class='evidence'>" + esc(f.payload) + "</pre>" if f.payload else ""}
                    <pre class="evidence">{esc(f.evidence)}</pre>
                    <div class="remediation"><strong>Remediation:</strong> {esc(f.remediation)}</div>
                </div>
            </div>"""

        timeline_html = ""
        for log in self.actions_log:
            timeline_html += f"<li><strong>{esc(log['timestamp'])}</strong>: {esc(log['action'])} — {esc(log['details'])}</li>\n"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Red Team Report — {esc(self.client_name)}</title>
<style>
    *{{margin:0;padding:0;box-sizing:border-box;}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;padding:2rem;}}
    .container{{max-width:960px;margin:0 auto;}}
    h1{{color:#58a6ff;margin-bottom:.5rem;}}
    h2{{color:#f0f6fc;border-bottom:1px solid #30363d;padding-bottom:.5rem;margin:2rem 0 1rem;}}
    .meta{{color:#8b949e;margin-bottom:2rem;}}
    .score-box{{background:linear-gradient(135deg,#161b22,#21262d);border:1px solid #30363d;border-radius:12px;padding:1.5rem;text-align:center;margin:1.5rem 0;}}
    .score-value{{font-size:3rem;font-weight:700;color:{"#dc3545" if score>=7 else "#fd7e14" if score>=4 else "#28a745"};}}
    .finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:1rem 0;overflow:hidden;}}
    .finding-header{{padding:1rem;display:flex;align-items:center;gap:1rem;background:#21262d;}}
    .finding-body{{padding:1rem;}}
    .badge{{color:#fff;padding:2px 10px;border-radius:12px;font-size:.85rem;font-weight:600;}}
    .cvss{{margin-left:auto;color:#8b949e;font-size:.9rem;}}
    pre.evidence{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:1rem;overflow-x:auto;font-size:.85rem;margin:.5rem 0;}}
    .remediation{{background:#0d1117;border-left:3px solid #3fb950;padding:.75rem;margin-top:.75rem;border-radius:4px;}}
    code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:.9rem;}}
    table{{width:100%;border-collapse:collapse;margin:1rem 0;}}
    th,td{{text-align:left;padding:.75rem;border-bottom:1px solid #30363d;}}
    th{{background:#21262d;color:#f0f6fc;}}
    ul.timeline{{list-style:none;padding-left:1rem;}}
    ul.timeline li{{padding:.25rem 0;border-left:2px solid #30363d;padding-left:1rem;margin-left:.5rem;}}
</style>
</head>
<body>
<div class="container">
    <h1>🔴 Red Team Engagement Report</h1>
    <div class="meta">
        <p>Client: {esc(self.client_name)} | Target: {esc(self.target_url)} | Date: {now}</p>
    </div>

    <h2>Executive Summary</h2>
    <p>{len(self.findings)} vulnerabilities identified during adversarial emulation.</p>
    <div class="score-box">
        <div>Overall Risk Score</div>
        <div class="score-value">{score:.1f}/10</div>
    </div>

    <h2>Findings ({len(self.findings)})</h2>
    {findings_html}

    <h2>Operation Timeline</h2>
    <ul class="timeline">
        {timeline_html}
    </ul>
</div>
</body>
</html>"""

    # ── JSON Report ──────────────────────────────────────────────────────
    def generate_json_report(self) -> str:
        """Generate structured JSON report for SIEM integration."""
        data = {
            "report_type": "red_team_engagement",
            "client": self.client_name,
            "target": self.target_url,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "risk_score": self._calculate_risk_score(),
            "metadata": self.scan_metadata,
            "summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": {
                    sev: data["count"]
                    for sev, data in self._severity_counts().items()
                },
            },
            "findings": [asdict(f) for f in self.findings],
            "timeline": self.actions_log,
        }
        return json.dumps(data, indent=2, default=str)

    # ── Helpers ──────────────────────────────────────────────────────────
    def _calculate_risk_score(self) -> float:
        if not self.findings:
            return 0.0
        weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
        total = sum(weights.get(f.severity, 1) for f in self.findings)
        return min(10.0, total / max(len(self.findings), 1))

    def _severity_counts(self) -> Dict[str, Dict]:
        counts: Dict[str, Dict] = {}
        for f in self.findings:
            if f.severity not in counts:
                counts[f.severity] = {"count": 0, "total_cvss": 0.0}
            counts[f.severity]["count"] += 1
            counts[f.severity]["total_cvss"] += f.cvss_score
        for sev, data in counts.items():
            data["avg_cvss"] = data["total_cvss"] / data["count"] if data["count"] else 0
        return counts

    @staticmethod
    def _auto_remediation(vuln_type: str) -> str:
        """Generate standard remediation text."""
        remediations = {
            "sql_injection": "Use parameterized queries (prepared statements). Validate and sanitize all user inputs. Apply least-privilege database access.",
            "xss": "Encode all output. Use Content-Security-Policy headers. Validate input on server side.",
            "ssti": "Avoid passing user input to template engines. Use sandboxed environments. Validate and sanitize all inputs.",
            "rce": "Avoid executing user-controlled input. Use allowlists for command execution. Apply sandboxing.",
            "lfi": "Validate file paths against an allowlist. Do not allow user-controlled paths. Use chroot or similar isolation.",
            "auth_bypass": "Implement proper authentication checks on all endpoints. Use secure session management.",
            "info_disclosure": "Remove sensitive information from error messages. Disable verbose error reporting in production.",
        }
        return remediations.get(vuln_type, "Review and remediate according to security best practices.")


# Factory
def get_reporter(client_name: str, target_url: str = "") -> RedTeamReporter:
    return RedTeamReporter(client_name, target_url)
