"""
Evidence Store — Structured evidence consolidation engine.

Replaces ad-hoc string lists with typed, deduplicated, queryable storage.
Supports merge across phases and structured export (JSON, summary).
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

logger = logging.getLogger("cerberus.evidence_store")


class EvidenceSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceType(str, Enum):
    SQLI = "sql_injection"
    XSS = "xss"
    SSTI = "ssti"
    RCE = "rce"
    LFI = "lfi"
    NOSQL = "nosql_injection"
    ENUM = "enumeration"
    AUTH_BYPASS = "auth_bypass"
    INFO_DISCLOSURE = "info_disclosure"
    OTHER = "other"


class EvidenceItem(BaseModel):
    """Single piece of evidence from a scan."""
    id: str = ""
    scan_id: str
    engine: str
    vector: str
    vuln_type: EvidenceType = EvidenceType.OTHER
    severity: EvidenceSeverity = EvidenceSeverity.INFO
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    payload: str = ""
    parameter: str = ""
    url: str = ""
    response_snippet: str = ""
    dbms: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)
    mitre_attack_id: str = ""

    def compute_id(self) -> str:
        """Deterministic ID based on payload + vector + engine."""
        raw = f"{self.engine}|{self.vector}|{self.payload}|{self.parameter}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.compute_id()


class EvidenceStore:
    """
    Central evidence repository with deduplication and structured export.

    Usage:
        store = EvidenceStore(scan_id="scan_001")
        store.add(EvidenceItem(scan_id="scan_001", engine="sqlmap", ...))
        report = store.export_json()
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._items: Dict[str, EvidenceItem] = {}  # id -> item
        self._duplicates_skipped: int = 0

    @property
    def count(self) -> int:
        return len(self._items)

    def add(self, item: EvidenceItem) -> bool:
        """Add evidence item. Returns False if duplicate."""
        item_id = item.compute_id()
        if item_id in self._items:
            existing = self._items[item_id]
            # Keep the one with higher confidence
            if item.confidence > existing.confidence:
                self._items[item_id] = item
                logger.debug(f"Evidence {item_id} updated with higher confidence")
                return True
            self._duplicates_skipped += 1
            logger.debug(f"Duplicate evidence skipped: {item_id}")
            return False
        self._items[item_id] = item
        logger.info(
            f"Evidence added: [{item.severity.value}] {item.vuln_type.value} "
            f"via {item.engine} on {item.vector}"
        )
        return True

    def add_many(self, items: List[EvidenceItem]) -> int:
        """Add multiple items. Returns count of new items added."""
        return sum(1 for item in items if self.add(item))

    def get_all(self) -> List[EvidenceItem]:
        """All evidence items, sorted by severity then confidence."""
        severity_order = {
            EvidenceSeverity.CRITICAL: 0,
            EvidenceSeverity.HIGH: 1,
            EvidenceSeverity.MEDIUM: 2,
            EvidenceSeverity.LOW: 3,
            EvidenceSeverity.INFO: 4,
        }
        return sorted(
            self._items.values(),
            key=lambda x: (severity_order.get(x.severity, 5), -x.confidence),
        )

    def get_by_severity(self) -> Dict[str, List[EvidenceItem]]:
        """Group evidence by severity level."""
        result: Dict[str, List[EvidenceItem]] = {}
        for item in self.get_all():
            key = item.severity.value
            result.setdefault(key, []).append(item)
        return result

    def get_by_engine(self) -> Dict[str, List[EvidenceItem]]:
        """Group evidence by scanning engine."""
        result: Dict[str, List[EvidenceItem]] = {}
        for item in self.get_all():
            result.setdefault(item.engine, []).append(item)
        return result

    def get_by_type(self) -> Dict[str, List[EvidenceItem]]:
        """Group evidence by vulnerability type."""
        result: Dict[str, List[EvidenceItem]] = {}
        for item in self.get_all():
            result.setdefault(item.vuln_type.value, []).append(item)
        return result

    def get_confirmed(self, min_confidence: float = 0.7) -> List[EvidenceItem]:
        """Get only high-confidence findings."""
        return [i for i in self.get_all() if i.confidence >= min_confidence]

    def merge(self, other: "EvidenceStore") -> int:
        """Merge another store into this one. Returns count of new items."""
        return self.add_many(list(other._items.values()))

    def export_json(self) -> str:
        """Export all evidence as structured JSON."""
        data = {
            "scan_id": self.scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": self.count,
            "duplicates_skipped": self._duplicates_skipped,
            "severity_breakdown": {
                sev: len(items)
                for sev, items in self.get_by_severity().items()
            },
            "findings": [
                item.model_dump(mode="json") for item in self.get_all()
            ],
        }
        return json.dumps(data, indent=2, default=str)

    def export_summary(self) -> str:
        """Export executive summary as text."""
        by_sev = self.get_by_severity()
        confirmed = self.get_confirmed()
        lines = [
            f"=== Evidence Summary for scan {self.scan_id} ===",
            f"Total findings: {self.count}",
            f"Confirmed (≥70% confidence): {len(confirmed)}",
            f"Duplicates skipped: {self._duplicates_skipped}",
            "",
            "Severity breakdown:",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_sev.get(sev, []))
            if count > 0:
                lines.append(f"  {sev.upper()}: {count}")

        if confirmed:
            lines.append("")
            lines.append("Top findings:")
            for item in confirmed[:5]:
                lines.append(
                    f"  [{item.severity.value.upper()}] {item.vuln_type.value} "
                    f"on {item.parameter or item.vector} "
                    f"via {item.engine} (confidence: {item.confidence:.0%})"
                )

        return "\n".join(lines)

    def save_to_file(self, path: str) -> None:
        """Persist evidence store to JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.export_json())
        logger.info(f"Evidence store saved to {path}")

    @classmethod
    def load_from_file(cls, path: str) -> "EvidenceStore":
        """Load evidence store from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        store = cls(scan_id=data.get("scan_id", "unknown"))
        for finding in data.get("findings", []):
            try:
                item = EvidenceItem(**finding)
                store.add(item)
            except Exception as e:
                logger.warning(f"Skipping malformed finding: {e}")
        return store
