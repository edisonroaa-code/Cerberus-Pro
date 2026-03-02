import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Union


def redact_local_info(text: Any) -> Any:
    """
    Redact sensitive local information (absolute paths, usernames) from text or lists.
    Replaces common local path patterns with neutral tokens.
    """
    if isinstance(text, list):
        return [redact_local_info(item) for item in text]
    if not isinstance(text, str):
        return text

    # Define patterns to redact
    # 1. Absolute Windows paths (e.g., C:\Users\Username\...)
    # We replace the user home part while keeping the relative project structure if possible
    text = re.sub(r'[A-Za-z]:\\Users\\[^\\]+\\', r'<CERBERUS_HOME>\\', text)
    
    # 2. General path-like strings that might contain the username
    # This is a bit more aggressive to ensure coverage
    text = re.sub(r'/Users/[^/]+/', r'<CERBERUS_HOME>/', text)
    
    # 3. Specific known local path to this installation if detected
    # (Optional: could pass project_root dynamically, but regex above handles most cases)
    
    return text


class SmartFilterEngine:
    """Classify SQLMap output lines and suppress noisy output."""

    CRITICAL_PATTERNS = [
        r"(?i)\bis vulnerable\b",
        r"(?i)\bappears to be injectable\b",
        r"(?i)\bidentified the following injection point",
        r"(?i)\bback-end dbms is\b",
        r"(?i)\baccess denied\b",
        r"(?i)\bpermission denied\b",
    ]
    HIGH_PATTERNS = [
        r"(?i)\berror-based\b",
        r"(?i)\btime-based\b",
        r"(?i)\bunion query\b",
        r"(?i)\bstacked queries\b",
        r"(?i)\bretrieved:\b",
        r"(?i)\bcurrent (user|database):\b",
    ]
    MEDIUM_PATTERNS = [
        r"(?i)\btesting\b",
        r"(?i)\bheuristic\b",
        r"(?i)\bparameter\b",
        r"(?i)\bfetching\b",
        r"(?i)\bdumping\b",
        r"(?i)\bdbms\b",
    ]
    NOISE_PATTERNS = [
        r"\|_",
        r"---",
        r"https://sqlmap\.org",
        r"(?i)\busing '.+\.csv' as the CSV\b",
        r"(?i)\blegal disclaimer\b",
        r"(?i)\bstarted at\b",
        r"(?i)\bending @\b",
    ]

    def __init__(self) -> None:
        self.total_lines = 0
        self.noise_lines = 0
        self.severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "NOISE": 0}

    def classify(self, line: str) -> str:
        self.total_lines += 1
        if self._match_any(self.NOISE_PATTERNS, line):
            self.noise_lines += 1
            self.severity_counts["NOISE"] += 1
            return "NOISE"
        if self._match_any(self.CRITICAL_PATTERNS, line):
            self.severity_counts["CRITICAL"] += 1
            return "CRITICAL"
        if self._match_any(self.HIGH_PATTERNS, line):
            self.severity_counts["HIGH"] += 1
            return "HIGH"
        self.severity_counts["MEDIUM"] += 1
        return "MEDIUM"

    def keep_for_clean_view(self, severity: str) -> bool:
        return severity in ("CRITICAL", "HIGH", "MEDIUM")

    def stats(self) -> Dict[str, object]:
        reduced_pct = round((self.noise_lines / self.total_lines) * 100, 2) if self.total_lines else 0.0
        return {
            "total_lines": self.total_lines,
            "noise_lines": self.noise_lines,
            "noise_reduction_pct": reduced_pct,
            "severity_counts": self.severity_counts,
        }

    @staticmethod
    def _match_any(patterns: List[str], line: str) -> bool:
        return any(re.search(p, line) for p in patterns)


class FindingParser:
    """Extract structured findings from textual scan output."""

    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    API_KEY_RE = re.compile(r"(?i)\b(?:api[_-]?key|token)\b[^\n:=]*[:=]\s*([A-Za-z0-9_\-]{16,})")
    HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
    CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    USER_PASS_RE = re.compile(r"(?i)\b(?:user|username|login)\b[^=\n:]*[:=]\s*([^\s,;]+).{0,30}?(?:pass|password|pwd)\b[^=\n:]*[:=]\s*([^\s,;]+)")
    DB_RE = re.compile(r"(?i)\b(?:current database|database)\s*:\s*([A-Za-z0-9_\-$]+)")

    def __init__(self) -> None:
        self.findings = {
            "credentials": [],
            "hashes": [],
            "emails": [],
            "api_keys": [],
            "credit_cards": [],
            "databases": [],
            "raw_hits": [],
        }

    def feed(self, line: str) -> None:
        emails = self.EMAIL_RE.findall(line)
        keys = self.API_KEY_RE.findall(line)
        hashes = self.HASH_RE.findall(line)
        cards = [cc for cc in self.CC_RE.findall(line) if self._looks_like_card(cc)]
        creds = self.USER_PASS_RE.findall(line)
        dbs = self.DB_RE.findall(line)

        if emails:
            self._append_unique("emails", emails)
        if keys:
            self._append_unique("api_keys", keys)
        if hashes:
            self._append_unique("hashes", hashes)
        if cards:
            self._append_unique("credit_cards", cards)
        if creds:
            norm = [f"{u}:{p}" for (u, p) in creds]
            self._append_unique("credentials", norm)
        if dbs:
            self._append_unique("databases", dbs)

        if any([emails, keys, hashes, cards, creds, dbs]):
            self._append_unique("raw_hits", [line.strip()])

    def summary(self) -> Dict[str, object]:
        counts = {k: len(v) for k, v in self.findings.items() if isinstance(v, list)}
        return {"counts": counts, "findings": self.findings}

    def _append_unique(self, key: str, values: List[str]) -> None:
        bucket = self.findings[key]
        for value in values:
            if value not in bucket:
                bucket.append(value)

    @staticmethod
    def _looks_like_card(value: str) -> bool:
        digits = re.sub(r"\D", "", value)
        return 13 <= len(digits) <= 19


def build_multi_profile_reports(
    target: str,
    vulnerable: bool,
    verdict: str,
    conclusive: bool,
    extracted_data: List[str],
    filter_stats: Dict[str, object],
    parser_summary: Dict[str, object],
) -> Dict[str, object]:
    """Build executive, technical and forensic report bodies."""
    now_iso = datetime.now(timezone.utc).isoformat()
    verdict_norm = str(verdict or "").strip().upper() or ("VULNERABLE" if vulnerable else "NO_VULNERABLE")
    verdict_norm = verdict_norm.replace(" ", "_")
    status_line = verdict_norm.replace("_", " ")
    severity = "CRITICAL" if vulnerable else ("LOW" if conclusive else "UNKNOWN")

    executive_md = (
        f"# Executive Report\n\n"
        f"- Target: {target}\n"
        f"- Status: {status_line}\n"
        f"- Conclusive: {'YES' if conclusive else 'NO'}\n"
        f"- Severity: {severity}\n"
        f"- Evidence points: {len(extracted_data)}\n"
        f"- Noise reduced: {filter_stats.get('noise_reduction_pct', 0)}%\n"
    )

    technical = {
        "target": target,
        "timestamp": now_iso,
        "vulnerable": vulnerable,
        "verdict": verdict_norm,
        "conclusive": conclusive,
        "evidence": extracted_data,
        "filter": filter_stats,
        "parser": parser_summary,
    }

    forensic_payload = {
        "target": target,
        "timestamp": now_iso,
        "vulnerable": vulnerable,
        "verdict": verdict_norm,
        "conclusive": conclusive,
        "evidence_count": len(extracted_data),
        "parser_counts": parser_summary.get("counts", {}),
    }
    canonical = json.dumps(forensic_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    sha256 = hashlib.sha256(canonical).hexdigest()
    forensic = {
        "chain_of_custody": forensic_payload,
        "sha256": sha256,
        "immutable_payload": canonical.decode("utf-8"),
    }

    return {
        "executive": executive_md,
        "technical": technical,
        "forensic": forensic,
    }


def synthesize_structured_findings(target: str, results: List[Dict]) -> List[Dict]:
    """
    Convert raw engine results into structured Finding-like dicts with PoC.
    Returns list of dicts suitable for JSON persistence.
    """
    from backend.engines.base import VulnerabilityType, Severity

    out: List[Dict] = []
    for r in results:
        try:
            vec = str(r.get("vector") or r.get("engine") or "sqlmap").upper()
            vulnerable = bool(r.get("vulnerable"))
            evidence = [str(e) for e in (r.get("evidence") or []) if str(e).strip()]
            exit_code = int(r.get("exit_code") or 0)
            
            # Sanitize command for privacy
            raw_cmd = r.get("command") or []
            cmd = redact_local_info(raw_cmd)

            # Heuristics: assign type and confidence
            if "UNION" in vec or "ERROR" in vec or "STACKED" in vec or "BOOLEAN" in vec or "TIME" in vec:
                vtype = VulnerabilityType.SQL_INJECTION
            else:
                vtype = VulnerabilityType.SECURITY_MISC

            if vulnerable and evidence:
                confidence = 0.9
            elif vulnerable and not evidence:
                confidence = 0.65
            elif exit_code == 0 and evidence:
                confidence = 0.7
            else:
                confidence = 0.3

            # Extract parameter and endpoint from command or evidence
            endpoint = str(r.get("target") or target)
            parameter = ""
            # Try to find parameter in evidence
            for ev in evidence:
                m = re.search(r"(?i)parameter\s+'([^']+)'", ev)
                if m:
                    parameter = m.group(1)
                    break
            if not parameter:
                # try parse from command
                if isinstance(cmd, list) and cmd:
                    joined = " ".join([str(x) for x in cmd])
                    m = re.search(r"-p\s+([^\s]+)", joined)
                    if m:
                        parameter = m.group(1)

            payload = evidence[0] if evidence else ""

            # DBMS extraction
            dbms = None
            for ev in evidence:
                mm = re.search(r"back-end dbms is\s*([A-Za-z0-9_\-]+)", ev, re.I)
                if mm:
                    dbms = mm.group(1)
                    break


            # PoC generator with DBMS-specific templates
            poctemplate = None
            try:
                dbms_l = (str(dbms or "").lower() if dbms else "")
                if isinstance(cmd, list) and cmd:
                    joined_cmd = " ".join([str(x) for x in cmd])
                    poctemplate = redact_local_info(joined_cmd)
                else:
                    # Generic curl fallback
                    param = parameter or "id"
                    sep = "&" if "?" in endpoint else "?"
                    poctemplate = f"curl '{endpoint}{sep}{param}=1'"

                # DBMS-specific nicer PoCs when DBMS known
                if dbms_l:
                    if "mysql" in dbms_l:
                        poctemplate = f"mysql -h <host> -u <user> -p -e \"SELECT 1;\""
                    elif "postgres" in dbms_l or "psql" in dbms_l:
                        poctemplate = f"psql postgresql://<user>@<host>:5432/<db> -c \"SELECT 1;\""
                    elif "mssql" in dbms_l or "sql server" in dbms_l:
                        poctemplate = f"curl 'jdbc:sqlserver://<host>;user=<user>;password=<pass>'"
                    elif "oracle" in dbms_l:
                        poctemplate = f"echo \"select 1 from dual;\" | sqlplus <user>/<pass>@<host>"
                    elif "sqlite" in dbms_l:
                        poctemplate = f"sqlite3 <file> 'select sqlite_version();'"
            except Exception:
                poctemplate = None

            # Improved confidence heuristics
            sev_score = 0.0
            # Base on explicit vulnerable flag and evidence richness
            if vulnerable:
                sev_score += 0.5
            if evidence:
                # more evidence lines -> higher confidence
                sev_score += min(0.35, 0.07 * len(evidence))
                # keyword boosts
                for ev in evidence:
                    el = str(ev).lower()
                    if "appears to be injectable" in el or "is vulnerable" in el or "es vulnerable" in el:
                        sev_score += 0.15
                    if "back-end dbms is" in el or "back-end dbms" in el or "dbms" in el:
                        sev_score += 0.05
            if exit_code == 0:
                sev_score += 0.05
            # Vector-specific adjustments
            if any(k in vec for k in ("UNION", "ERROR", "STACKED")):
                sev_score += 0.05
            if any(k in vec for k in ("TIME", "BOOLEAN")):
                sev_score += 0.02

            confidence = max(0.0, min(0.99, round(float(sev_score), 2)))

            severity = Severity.HIGH if confidence >= 0.75 else (Severity.MEDIUM if confidence >= 0.5 else Severity.LOW)

            out.append({
                "type": str(vtype.value),
                "endpoint": endpoint,
                "parameter": parameter,
                "payload": payload,
                "confidence": round(float(confidence), 2),
                "severity": severity.value,
                "evidence": evidence,
                "engine": str(r.get("engine") or r.get("vector") or "sqlmap"),
                "dbms": dbms,
                "poctemplate": poctemplate,
                "vector": vec,
            })
        except Exception:
            continue
    return out
