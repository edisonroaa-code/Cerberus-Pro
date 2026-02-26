"""
Cerberus Pro v4 - Engine Adapter Base Classes and Registry

Unified interface for all vulnerability scanning engines.
Every adapter implements the same async scan() interface.

No black boxes: Each engine reports findings in standardized Finding format.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum


class VulnerabilityType(str, Enum):
    """Standardized vulnerability types across all engines"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    XXE = "xxe"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTHENTICATION_BYPASS = "auth_bypass"
    DESERIALIZATION = "insecure_deserialize"
    SECURITY_MISC = "security_misc"
    WEAK_CRYPTO = "weak_crypto"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    EXPOSED_SERVICE = "exposed_service"
    DIRECTORY_LISTING = "directory_listing"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"


class Severity(str, Enum):
    """Severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Unified finding format across all engines"""
    type: VulnerabilityType
    endpoint: str
    parameter: str
    payload: str
    confidence: float  # 0-1
    severity: Severity
    evidence: List[str] = field(default_factory=list)
    engine: Optional[str] = None
    dbms: Optional[str] = None
    poctemplate: Optional[str] = None
    vector: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def __hash__(self):
        """Allow deduplication by (endpoint, parameter, type)"""
        return hash((self.endpoint, self.parameter, self.type))

    def dedup_key(self) -> tuple:
        """Key for deduplication across engines"""
        return (self.endpoint, self.parameter, self.type)


@dataclass
class EngineConfig:
    """Engine-specific configuration"""
    engine_id: str
    timeout_ms: int = 30000
    max_payloads: int = 100
    rate_limit_rps: float = 5.0
    custom_params: Dict = field(default_factory=dict)
    enabled: bool = True


class EngineAdapter(ABC):
    """
    Base class for all engine adapters.
    Subclasses must implement scan() and get_status().
    """

    def __init__(self, config: EngineConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    @abstractmethod
    async def scan(self, target: str, vectors: List[Dict]) -> List[Finding]:
        """
        Scan target against vectors.

        Args:
            target: URL or asset to scan (e.g., "https://example.com")
            vectors: List of vectors to test, each with:
                {
                    "endpoint": "/api/users",
                    "parameter": "id",
                    "method": "GET",
                    "payloads": ["' OR 1=1", ...]
                }

        Returns:
            List of Finding objects discovered.
        """
        pass

    @abstractmethod
    def get_status(self) -> Dict:
        """
        Return engine health and metrics.

        Returns:
            {
                "engine": str,
                "status": "ready" | "running" | "stopped" | "error",
                "findings": int,
                "duration_ms": int,
                "errors": int
            }
        """
        pass

    @abstractmethod
    async def stop(self):
        """Gracefully stop scanning"""
        pass


# Global engine registry
_engines: Dict[str, EngineAdapter] = {}


def register_engine(name: str, adapter: EngineAdapter) -> None:
    """Register an engine adapter instance"""
    if not isinstance(adapter, EngineAdapter):
        raise TypeError(f"{adapter} must be an instance of EngineAdapter")
    _engines[name] = adapter


def get_engine(name: str) -> Optional[EngineAdapter]:
    """Get an engine instance by name"""
    if name not in _engines:
        return None
    return _engines[name]


def list_engines() -> List[str]:
    """List all registered engines"""
    return sorted(list(_engines.keys()))


def is_engine_registered(name: str) -> bool:
    """Check if engine is registered"""
    return name in _engines
