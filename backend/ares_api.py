#!/usr/bin/env python3
"""
Cerberus Pro API - Secure Backend with Enterprise Authentication
Full PHASE 1 Security Implementation
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Query, status
from fastapi.responses import JSONResponse
from starlette.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi.util import get_remote_address
    _SLOWAPI_AVAILABLE = True
except Exception:
    Limiter = None
    RateLimitExceeded = Exception  # type: ignore
    SlowAPIMiddleware = None
    def _rate_limit_exceeded_handler(*args, **kwargs):  # type: ignore
        return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"detail": "Rate limit exceeded"})
    def get_remote_address(request: Request) -> str:  # type: ignore
        return request.client.host if request and request.client else "unknown"
    _SLOWAPI_AVAILABLE = False

try:
    import redis.asyncio as redis_async  # type: ignore
    _REDIS_AVAILABLE = True
except Exception:
    redis_async = None  # type: ignore
    _REDIS_AVAILABLE = False

from starlette.middleware.base import BaseHTTPMiddleware
import sys
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
from pathlib import Path
from dotenv import load_dotenv

# Add backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
from pydantic import BaseModel
import subprocess
import shlex
import re
import socket
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import logging
import json
import secrets
import hmac
import sys
from urllib.parse import urlparse
from urllib.parse import parse_qs
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

# Stealth imports
from ares_engine.stealth.header_scrubber import HeaderScrubber
from ares_engine.stealth.dns_validator import DNSValidator

# Security imports
from auth_security import (
    JWTManager, PasswordManager, APIKeyManager, MFAManager, AccessControl,
    User, UserCreate, LoginRequest, TokenResponse, Role, Permission,
    SecurityConfig, get_current_user, require_permission, require_role,
    JWTPayload, AuditLog, APIKeyModel, MFASetup, TokenType, ROLE_PERMISSIONS,
    Agent, AgentCredentials, ResetPasswordRequest
)

# Services
from services.email_service import EmailService
from v4_intelligence import SmartFilterEngine, FindingParser, build_multi_profile_reports, synthesize_structured_findings
from v4_omni_surface import (
    PolymorphicEvasionEngine,
    BrowserStealth,
    engine_registry,
    calibration_waf_detect,
    suspect_defended_target,
    build_vector_commands,
    run_sqlmap_vector,
    direct_db_reachability,
    websocket_exploit,
    mqtt_exploit,
    grpc_deep_fuzz_probe,
    DifferentialResponseValidator,
    TLSFingerprintManager,
)
from core.coverage_ledger import (
    CoverageLedger,
    ConclusiveBlocker,
    PhaseCompletionRecord,
)
from core.coverage_contract_v1 import (
    COVERAGE_SCHEMA_VERSION_V1,
    ConclusiveBlockerV1,
    CoverageResponseV1,
    CoverageSummaryV1,
    CoveragePhaseRecordV1,
    CoverageVectorRecordV1,
    VectorRecordsPageV1,
    adapt_legacy_blockers,
    issue_verdict_v1,
)
from core.coverage_mapper import (
    _build_default_vector_page as _coverage_mapper_build_default_vector_page,
    _coverage_public_payload as _coverage_mapper_public_payload,
    _safe_phase_notes as _coverage_mapper_safe_phase_notes,
    _safe_phase_status as _coverage_mapper_safe_phase_status,
    _to_phase_records_v1 as _coverage_mapper_to_phase_records_v1,
    _to_vector_records_v1 as _coverage_mapper_to_vector_records_v1,
)
from core.audit_chain_store import (
    append_audit_chain as _audit_store_append_audit_chain,
    init_audit_db as _audit_store_init_audit_db,
    verify_audit_chain as _audit_store_verify_audit_chain,
)
from core.job_runtime import (
    ensure_job_background_tasks as _job_runtime_ensure_job_background_tasks,
    enqueue_job_memory as _job_runtime_enqueue_job_memory,
    init_job_queue_backend as _job_runtime_init_job_queue_backend,
    job_score as _job_runtime_job_score,
    queue_enqueue as _job_runtime_queue_enqueue,
    queue_pop as _job_runtime_queue_pop,
    queue_reconciler_loop as _job_runtime_queue_reconciler_loop,
    refresh_queue_backlog_metric as _job_runtime_refresh_queue_backlog_metric,
    task_runtime_state as _job_runtime_task_runtime_state,
)
from core.job_worker import (
    job_heartbeat_loop as _job_worker_heartbeat_loop,
    job_worker_loop as _job_worker_worker_loop,
)
from core.job_kind import (
    job_kind_candidates as _job_kind_candidates_impl,
    normalize_job_kind as _normalize_job_kind_impl,
)
from core.job_config_norm import (
    normalize_classic_to_unified_cfg as _job_cfg_normalize_classic_to_unified_cfg,
    normalize_unified_job_cfg as _job_cfg_normalize_unified_job_cfg,
)
from core.process_guard import (
    host_allowed as _process_guard_host_allowed,
    is_ip as _process_guard_is_ip,
    normalize_host as _process_guard_normalize_host,
    start_sqlmap_process as _process_guard_start_sqlmap_process,
    terminate_process_tree as _process_guard_terminate_process_tree,
)
from core.worker_identity import build_worker_payload as _worker_identity_build_worker_payload
from core.unified_target_policy import (
    validate_unified_target_policy as _target_policy_validate_unified_target_policy,
)
from core.target_validation import (
    validate_network_host as _target_validation_validate_network_host,
    validate_target as _target_validation_validate_target,
)
from core.log_output import (
    sanitize_line as _log_output_sanitize_line,
    translate_log as _log_output_translate_log,
)
from core.omni_scan_runtime import (
    analyze_omni_results_for_verdict as _omni_runtime_analyze_results_for_verdict,
    build_engine_vectors_for_target as _omni_runtime_build_engine_vectors_for_target,
    build_requested_engines as _omni_runtime_build_requested_engines,
    compute_defended_heuristics_seed as _omni_runtime_compute_defended_heuristics_seed,
    merge_defended_heuristics as _omni_runtime_merge_defended_heuristics,
    omni_reason_human as _omni_runtime_reason_human,
    prepare_omni_scan_context as _omni_runtime_prepare_scan_context,
)
from core.omni_history import (
    build_history_data as _omni_history_build_history_data,
    make_history_paths as _omni_history_make_history_paths,
    persist_encrypted_artifact as _omni_history_persist_encrypted_artifact,
    persist_history_json as _omni_history_persist_history_json,
    set_evidence_count as _omni_history_set_evidence_count,
)
from core.omni_web_execution import (
    execute_web_mode_phases as _omni_web_execute_mode_phases,
)
from core.omni_engine_scan import (
    run_registered_engines_unified as _omni_engine_run_registered_engines_unified,
)
from core.omni_nonweb_execution import (
    execute_nonweb_mode as _omni_nonweb_execute_mode,
)
from core.omni_coverage_finalize import (
    finalize_omni_coverage as _omni_finalize_coverage,
)
from core.unified_multilevel_job import (
    UnifiedMultilevelJobDeps,
    run_unified_multilevel_job as _run_unified_multilevel_job_impl,
)
from core.websocket_runtime import (
    WebsocketRuntimeDeps,
    broadcast as _ws_broadcast_impl,
    websocket_agent_endpoint as _ws_agent_endpoint_impl,
    websocket_endpoint as _ws_endpoint_impl,
)
from core.audit_runtime import (
    AuditRuntimeDeps,
    audit_log as _audit_runtime_log_impl,
    list_audit_logs as _audit_runtime_list_logs_impl,
    verify_audit_chain as _audit_runtime_verify_chain_impl,
)
from core.system_ops_runtime import (
    SystemOpsRuntimeDeps,
    admin_kick_jobs_payload as _system_ops_admin_kick_jobs_payload_impl,
    health_payload as _system_ops_health_payload_impl,
    status_payload as _system_ops_status_payload_impl,
)
from core.job_control_runtime import (
    JobControlRuntimeDeps,
    get_job_coverage_payload as _job_control_get_job_coverage_payload_impl,
    get_job_payload as _job_control_get_job_payload_impl,
    get_scan_status_payload as _job_control_get_scan_status_payload_impl,
    list_jobs_payload as _job_control_list_jobs_payload_impl,
    retry_job_payload as _job_control_retry_job_payload_impl,
    stop_job_payload as _job_control_stop_job_payload_impl,
    stop_scan_payload as _job_control_stop_scan_payload_impl,
)
from core.job_persistence_runtime import (
    JobPersistenceRuntimeDeps,
    create_job as _job_persist_create_job_impl,
    fallback_coverage_response_from_job as _job_persist_fallback_coverage_response_from_job_impl,
    get_job as _job_persist_get_job_impl,
    get_job_coverage_v1 as _job_persist_get_job_coverage_v1_impl,
    list_jobs as _job_persist_list_jobs_impl,
    update_job as _job_persist_update_job_impl,
)
from core.orchestrator_fsm import Orchestrator, OrchestratorPhase
from core.jobs_sqlite import (
    count_jobs as _jobs_sqlite_count_jobs,
    create_job as _jobs_sqlite_create_job,
    get_job as _jobs_sqlite_get_job,
    init_jobs_db as _jobs_sqlite_init_jobs_db,
    latest_active_scan_id as _jobs_sqlite_latest_active_scan_id,
    list_jobs as _jobs_sqlite_list_jobs,
    list_queued_job_ids as _jobs_sqlite_list_queued_job_ids,
    recover_running_jobs_on_startup as _jobs_sqlite_recover_running_jobs_on_startup,
    update_job as _jobs_sqlite_update_job,
)
from core.runtime_state import CerberusState
from core.scan_utils import (
    AUTOPILOT_MAX_PHASE,
    OMNI_ALLOWED_MODES,
    OMNI_ALLOWED_VECTORS,
    _apply_autopilot_policy as _scan_utils_apply_autopilot_policy,
    _autopilot_difficulty as _scan_utils_autopilot_difficulty,
    _default_unified_vectors_from_cfg as _scan_utils_default_unified_vectors_from_cfg,
    _ensure_unified_cfg_aliases as _scan_utils_ensure_unified_cfg_aliases,
    _merge_tampers as _scan_utils_merge_tampers,
    _normalize_unified_scan_cfg as _scan_utils_normalize_unified_scan_cfg,
    _read_unified_runtime_cfg as _scan_utils_read_unified_runtime_cfg,
    _safe_history_path as _scan_utils_safe_history_path,
    _target_slug as _scan_utils_target_slug,
    _validate_host_port as _scan_utils_validate_host_port,
    validate_omni_config as _scan_utils_validate_omni_config,
)
from core.worker_runner import run_standalone_worker as _worker_runner_run_standalone_worker
from db.postgres_store import PostgresStore
from routers.verdicts import router as verdicts_router
from routers.engines import router as engines_router
from exploits.metasploit_bridge import MetasploitBridge
from c2.c2_server import C2Server
from exfiltration.dns_tunnel import DNSTunnelListener
from exfiltration.icmp_exfil import ICMPListener
from payloads.payload_generator import PayloadGenerator
from privesc.privesc_engine import PrivEscEngine
from governance.policy_engine import get_policy_engine, ActionType


# ============================================================================
# CONFIGURATION
# ============================================================================

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from project root .env (if present)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

# Security config
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development') # Default to dev for local testing
DISABLE_LOCAL_DEV_WS = os.environ.get('DISABLE_LOCAL_DEV_WS', '').lower() in ('1', 'true', 'yes')
WS_HANDSHAKE_DEBUG = os.environ.get('WS_HANDSHAKE_DEBUG', '').lower() in ('1', 'true', 'yes')
SQLMAP_PATH = os.environ.get('CERBERUS_SQLMAP_PATH', os.path.join(os.path.dirname(__file__), '..', 'ares_engine', 'sqlmap.py'))
ALLOWED_TARGETS = os.environ.get('ALLOWED_TARGETS', '').split(',') if os.environ.get('ALLOWED_TARGETS') else []
HISTORY_DIR = os.environ.get("HISTORY_DIR", os.path.join(os.path.dirname(__file__), 'history'))
os.makedirs(HISTORY_DIR, exist_ok=True)

# History storage policy:
# - In development: keep plaintext JSON for convenience.
# - In production: default to encrypted-only (summary JSON + .enc), unless explicitly overridden.
HISTORY_STORE_PLAIN_JSON = os.environ.get("HISTORY_STORE_PLAIN_JSON", "").strip().lower()
if HISTORY_STORE_PLAIN_JSON in ("1", "true", "yes"):
    HISTORY_STORE_PLAIN = True
elif HISTORY_STORE_PLAIN_JSON in ("0", "false", "no"):
    HISTORY_STORE_PLAIN = False
else:
    HISTORY_STORE_PLAIN = (ENVIRONMENT == "development")

RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'false').lower() == 'true' # Disabled by default for dev
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "100/minute")
SENTRY_DSN = os.environ.get('SENTRY_DSN', '').strip()
SCAN_TIMEOUT_TOTAL_SECONDS = int(os.environ.get("SCAN_TIMEOUT_TOTAL_SECONDS", "1800"))
ALLOWED_WEB_SCHEMES = {"http", "https"}
VALIDATE_REDIRECT_CHAIN = os.environ.get("VALIDATE_REDIRECT_CHAIN", "true").lower() in ("1", "true", "yes")
AUDIT_DB_PATH = os.path.join(os.path.dirname(__file__), "audit_log.db")
AUDIT_DB_PATH = os.environ.get("AUDIT_DB_PATH", AUDIT_DB_PATH)
JOBS_DB_PATH = os.environ.get("JOBS_DB_PATH", os.path.join(os.path.dirname(__file__), "jobs.db"))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SCAN_RLIMIT_CPU_SECONDS = int(os.environ.get("SCAN_RLIMIT_CPU_SECONDS", "900"))
SCAN_RLIMIT_AS_MB = int(os.environ.get("SCAN_RLIMIT_AS_MB", "2048"))
ALLOW_LOCAL_TARGETS = os.environ.get("ALLOW_LOCAL_TARGETS", "false").lower() in ("1", "true", "yes")

# Multi-instance job queue (Enterprise readiness)
JOB_QUEUE_BACKEND = os.environ.get("JOB_QUEUE_BACKEND", "memory").strip().lower()  # memory|redis
JOB_QUEUE_REDIS_URL = os.environ.get("JOB_QUEUE_REDIS_URL", REDIS_URL)
WORKER_ID = os.environ.get("WORKER_ID", f"{socket.gethostname()}:{os.getpid()}")
JOB_HEARTBEAT_SECONDS = int(os.environ.get("JOB_HEARTBEAT_SECONDS", "10"))
JOB_QUEUE_RECONCILE_SECONDS = int(os.environ.get("JOB_QUEUE_RECONCILE_SECONDS", "15"))
JOB_RUNNING_STALE_SECONDS = int(os.environ.get("JOB_RUNNING_STALE_SECONDS", "300"))
JOB_QUEUE_KEY = os.environ.get("JOB_QUEUE_KEY", "cerberus:jobs:zq")
JOB_LOCK_KEY_PREFIX = os.environ.get("JOB_LOCK_KEY_PREFIX", "cerberus:jobs:lock:")
EMBEDDED_JOB_WORKER = os.environ.get("EMBEDDED_JOB_WORKER", "true").strip().lower() in ("1", "true", "yes")
PG_STORE = PostgresStore.from_env(DATABASE_URL)

if (not EMBEDDED_JOB_WORKER) and (JOB_QUEUE_BACKEND != "redis"):
    logger.warning(
        "EMBEDDED_JOB_WORKER disabled with JOB_QUEUE_BACKEND=%s. "
        "Only redis backend supports external worker processes.",
        JOB_QUEUE_BACKEND,
    )


def _sqlmap_non_interactive_flags() -> List[str]:
    # Keep sqlmap deterministic in unattended runs.
    return [
        "--batch",
        "--disable-coloring",
        "--answers=follow=Y,redirect=Y,resend=Y,form=Y,blank=Y,quit=N",
    ]

def _scrub_sensitive(value):
    if isinstance(value, dict):
        redacted = {}
        for k, v in value.items():
            key = str(k).lower()
            if any(x in key for x in ("authorization", "cookie", "token", "password", "secret", "api_key")):
                redacted[k] = "***REDACTED***"
            else:
                redacted[k] = _scrub_sensitive(v)
        return redacted
    if isinstance(value, list):
        return [_scrub_sensitive(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'(?i)(token|password|secret|api[_-]?key)=([^&\s]+)', r'\1=***REDACTED***', value)
        value = re.sub(r'(?i)(authorization:\s*bearer\s+)[^\s]+', r'\1***REDACTED***', value)
    return value

def _sentry_before_send(event, hint):
    return _scrub_sensitive(event)

if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FastApiIntegration()],
        traces_sample_rate=float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '0.2')),
        environment=ENVIRONMENT,
        before_send=_sentry_before_send,
    )

from prometheus_client import REGISTRY

def _get_or_create_counter(name, desc, labels=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Counter(name, desc, labels or [])

def _get_or_create_gauge(name, desc):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Gauge(name, desc)

def _get_or_create_histogram(name, desc, labels=None, buckets=None):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return Histogram(name, desc, labels or [], buckets=buckets)

SCAN_START_TOTAL = _get_or_create_counter("cerberus_scan_start_total", "Total scan starts", ["kind"])
SCAN_STOP_TOTAL = _get_or_create_counter("cerberus_scan_stop_total", "Total scan stops", ["kind"])
ACTIVE_OMNI_SCANS = _get_or_create_gauge("cerberus_active_omni_scans", "Number of active omni scans")
WS_CONNECTIONS = _get_or_create_gauge("cerberus_ws_connections", "Active websocket connections")
VERDICT_TOTAL = _get_or_create_counter("cerberus_verdict_total", "Total verdicts emitted", ["verdict"])
INCONCLUSIVE_TOTAL = _get_or_create_counter("cerberus_inconclusive_total", "Total inconclusive verdict blockers", ["code"])
PREFLIGHT_FAIL_TOTAL = _get_or_create_counter("cerberus_preflight_fail_total", "Preflight dependency failures", ["dependency"])
QUEUE_BACKLOG = _get_or_create_gauge("cerberus_queue_backlog", "Current queued jobs backlog")
PHASE_DURATION_SECONDS = _get_or_create_histogram(
    "cerberus_phase_duration_seconds",
    "Phase execution duration in seconds",
    ["phase"],
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 900, 1800),
)
JOB_DURATION_SECONDS = _get_or_create_histogram(
    "cerberus_job_duration_seconds",
    "Job total duration in seconds",
    ["kind"],
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 900, 1800, 3600),
)

# ============================================================================
# STATE MANAGEMENT
# ============================================================================

class ScanProfile(BaseModel):
    name: str  # "stealth", "balanced", "aggressive", "god_mode"
    # ... (existing fields)

class ExploitPayload(BaseModel):
    module: str
    target: str
    port: int
    payload: str = "generic/shell_reverse_tcp"
    options: Optional[Dict[str, str]] = {}

class CommandPayload(BaseModel):
    command: str

class PivotPayload(BaseModel):
    network: str

class TaskPayload(BaseModel):
    type: str
    data: Dict
    priority: int = 5

class PayloadConfig(BaseModel):
    type: str # vbs, powershell, html
    details: Dict # command, url, etc

class PrivEscRequest(BaseModel):
    technique: str

state = CerberusState()

# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

def _rate_limit_key_func(request: Request) -> str:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
    if token:
        try:
            payload = JWTManager.verify_token(token)
            return f"user:{payload.sub}"
        except Exception:
            pass
    return f"ip:{get_remote_address(request)}"


def _build_limiter():
    if not _SLOWAPI_AVAILABLE:
        class _NoopLimiter:
            enabled = False
            def limit(self, *args, **kwargs):
                def _decorator(func):
                    return func
                return _decorator
        return _NoopLimiter()
    storage_uri = REDIS_URL if RATE_LIMIT_ENABLED else "memory://"
    return Limiter(
        key_func=_rate_limit_key_func,
        default_limits=[RATE_LIMIT_DEFAULT],
        storage_uri=storage_uri,
        headers_enabled=True,
        enabled=RATE_LIMIT_ENABLED,
    )


limiter = _build_limiter()

# ============================================================================
# APPLICATION SETUP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown"""
    logger.info("🔐 Cerberus Pro API starting - Security Mode ENABLED")
    _init_audit_db()
    _init_jobs_db()

    # Init optional Redis client for multi-instance job queue.
    await _init_job_queue_backend()

    if EMBEDDED_JOB_WORKER:
        # Recover job state on restart:
        # - running jobs cannot be resumed safely -> mark as interrupted.
        # - queued jobs are re-enqueued so the worker can continue.
        _jobs_recover_on_startup()
        await _enqueue_queued_jobs()
        await _ensure_job_background_tasks(force=True)
    else:
        logger.info("🧾 Embedded job worker disabled (EMBEDDED_JOB_WORKER=false)")
    
    # Create default admin user
    if not state.users:
        admin_id = "u_admin_001"
        admin_user = User(
            id=admin_id,
            username="admin",
            email="admin@cerberus.corp",
            full_name="System Administrator",
            role=Role.SUPER_ADMIN,
            created_at=datetime.now(timezone.utc),
            last_login=None,
            password_hash=PasswordManager.hash_password("CerberusPro2024!"),
            mfa_enabled=False
        )
        state.users[admin_id] = admin_user
        logger.info(f"👤 Default admin user created (ID: {admin_id})")
        
    yield
    logger.info("🔐 Cerberus Pro API shutting down")
    # Cleanup
    if state.job_worker_task and not state.job_worker_task.done():
        state.job_worker_task.cancel()
    if state.queue_reconciler_task and not state.queue_reconciler_task.done():
        state.queue_reconciler_task.cancel()
    if state.redis is not None:
        try:
            await state.redis.aclose()
        except Exception:
            pass
    if state.proc and state.proc.returncode is None:
        _terminate_process_tree(state.proc)

def _pg_enabled() -> bool:
    return PG_STORE is not None

def _job_count_db(*, user_id: Optional[str] = None, statuses: Optional[List[str]] = None) -> int:
    if _pg_enabled():
        try:
            return int(PG_STORE.count_jobs(user_id=user_id, statuses=statuses))
        except Exception:
            return 0
    return _jobs_sqlite_count_jobs(JOBS_DB_PATH, user_id=user_id, statuses=statuses)


LEGACY_JOB_KINDS = ("classic", "omni")
CANONICAL_JOB_KIND = "unified"


def _normalize_job_kind(kind: Any) -> str:
    return _normalize_job_kind_impl(
        kind,
        canonical_job_kind=CANONICAL_JOB_KIND,
        legacy_job_kinds=LEGACY_JOB_KINDS,
    )


def _job_kind_candidates(kind: Any) -> List[str]:
    return _job_kind_candidates_impl(
        kind,
        canonical_job_kind=CANONICAL_JOB_KIND,
        legacy_job_kinds=LEGACY_JOB_KINDS,
    )


def _read_unified_runtime_cfg(cfg: dict) -> dict:
    return _scan_utils_read_unified_runtime_cfg(cfg)


def _ensure_unified_cfg_aliases(cfg: dict) -> dict:
    return _scan_utils_ensure_unified_cfg_aliases(cfg)


def _job_latest_active_scan_id(user_id: str, kind: str) -> Optional[str]:
    kinds = _job_kind_candidates(kind)
    if _pg_enabled():
        try:
            return PG_STORE.latest_active_job_scan_id(user_id=str(user_id), kinds=kinds)
        except Exception:
            return None
    return _jobs_sqlite_latest_active_scan_id(JOBS_DB_PATH, user_id=str(user_id), kinds=kinds)

def _persist_scan_artifacts_db(
    *,
    scan_id: str,
    user_id: str,
    kind: str,
    target_url: str,
    mode: Optional[str],
    profile: Optional[str],
    status: str,
    verdict: Optional[str],
    conclusive: Optional[bool],
    vulnerable: Optional[bool],
    count: Optional[int],
    evidence_count: Optional[int],
    results_count: Optional[int],
    message: Optional[str],
    cfg: Optional[dict],
    coverage: Optional[dict],
    report_data: Optional[dict],
):
    if (not _pg_enabled()) or (not scan_id):
        return
    normalized_kind = _normalize_job_kind(kind)
    try:
        PG_STORE.persist_scan_artifacts(
            scan_id=str(scan_id),
            user_id=str(user_id),
            kind=normalized_kind,
            target_url=str(target_url or ""),
            mode=(str(mode) if mode else None),
            profile=(str(profile) if profile else None),
            status=str(status),
            verdict=(str(verdict) if verdict else None),
            conclusive=conclusive,
            vulnerable=vulnerable,
            count=count,
            evidence_count=evidence_count,
            results_count=results_count,
            message=(str(message) if message else None),
            cfg=cfg or {},
            coverage=coverage or {},
            report_data=report_data or {},
            finished_at=_job_now(),
        )
    except Exception as e:
        logger.warning(f"PostgreSQL artifacts persistence failed for {scan_id}: {e}")


def _emit_verdict_metrics(verdict: str, blockers: Optional[List[ConclusiveBlockerV1]] = None) -> None:
    verdict_value = str(verdict or "INCONCLUSIVE").upper()
    try:
        VERDICT_TOTAL.labels(verdict=verdict_value).inc()
    except Exception:
        pass
    if verdict_value != "INCONCLUSIVE":
        return
    for blocker in blockers or []:
        code = str(getattr(blocker, "code", "") or "unknown")
        try:
            INCONCLUSIVE_TOTAL.labels(code=code).inc()
        except Exception:
            continue


def _record_phase_durations_from_coverage(coverage: Dict[str, Any]) -> None:
    phase_records = coverage.get("phase_records")
    if not isinstance(phase_records, list):
        return
    for rec in phase_records:
        if not isinstance(rec, dict):
            continue
        phase = str(rec.get("phase") or "unknown")
        duration_ms = rec.get("duration_ms")
        try:
            seconds = max(0.0, float(duration_ms or 0) / 1000.0)
            PHASE_DURATION_SECONDS.labels(phase=phase).observe(seconds)
        except Exception:
            continue


def _record_job_duration(kind: str, coverage: Dict[str, Any]) -> None:
    summary = coverage.get("coverage_summary")
    if not isinstance(summary, dict):
        return
    try:
        duration_ms = int(summary.get("total_duration_ms") or 0)
        JOB_DURATION_SECONDS.labels(kind=str(kind or "unknown")).observe(max(0.0, duration_ms / 1000.0))
    except Exception:
        return


def _build_default_vector_page(limit: int = 50, cursor: int = 0) -> VectorRecordsPageV1:
    return _coverage_mapper_build_default_vector_page(limit=limit, cursor=cursor)


def _safe_phase_status(raw_status: Any) -> str:
    return _coverage_mapper_safe_phase_status(raw_status)


def _safe_phase_notes(notes: Any) -> List[str]:
    return _coverage_mapper_safe_phase_notes(notes)


def _to_phase_records_v1(records: Optional[List[Any]]) -> List[CoveragePhaseRecordV1]:
    return _coverage_mapper_to_phase_records_v1(records)


def _to_vector_records_v1(records: Optional[List[Any]]) -> List[CoverageVectorRecordV1]:
    return _coverage_mapper_to_vector_records_v1(records)


def _coverage_public_payload(response: CoverageResponseV1, *, legacy_reason_codes: Optional[List[str]] = None) -> Dict[str, Any]:
    return _coverage_mapper_public_payload(response, legacy_reason_codes=legacy_reason_codes)


def _persist_coverage_v1_db(coverage_response: CoverageResponseV1) -> None:
    if not _pg_enabled():
        return
    try:
        PG_STORE.persist_coverage_v1(
            scan_id=coverage_response.scan_id,
            version=coverage_response.version,
            job_status=coverage_response.job_status,
            verdict=coverage_response.verdict,
            conclusive=coverage_response.conclusive,
            vulnerable=coverage_response.vulnerable,
            coverage_summary=coverage_response.coverage_summary.model_dump(),
            conclusive_blockers=[b.model_dump() for b in coverage_response.conclusive_blockers],
            phase_records=[p.model_dump() for p in coverage_response.phase_records],
            vector_records=[v.model_dump(exclude={"id"}) for v in coverage_response.vector_records_page.items],
        )
    except Exception as e:
        logger.warning(f"PostgreSQL coverage.v1 persistence failed for {coverage_response.scan_id}: {e}")

def _jobs_recover_on_startup():
    # If the backend restarts, any "running" job is no longer controlled.
    # For multi-instance, a different worker might still be running it, but
    # with local process execution we must fail closed.
    if _pg_enabled():
        try:
            PG_STORE.recover_running_jobs(stale_seconds=JOB_RUNNING_STALE_SECONDS)
            return
        except Exception as e:
            logger.warning(f"PostgreSQL recover-on-startup failed, falling back to SQLite: {e}")

    _jobs_sqlite_recover_running_jobs_on_startup(
        JOBS_DB_PATH,
        stale_seconds=JOB_RUNNING_STALE_SECONDS,
        now_iso=_job_now(),
    )

async def _init_job_queue_backend():
    await _job_runtime_init_job_queue_backend(
        state=state,
        job_queue_backend=JOB_QUEUE_BACKEND,
        redis_available=_REDIS_AVAILABLE,
        redis_module=redis_async,
        redis_url=JOB_QUEUE_REDIS_URL,
        worker_id=WORKER_ID,
        logger=logger,
    )

def _job_score(priority: int, created_at_iso: str) -> float:
    return _job_runtime_job_score(priority, created_at_iso)


async def _refresh_queue_backlog_metric() -> None:
    await _job_runtime_refresh_queue_backlog_metric(
        pg_enabled=_pg_enabled(),
        pg_store=PG_STORE,
        job_count_db=_job_count_db,
        queue_backlog_metric=QUEUE_BACKLOG,
    )

async def _queue_enqueue(scan_id: str, *, priority: int = 0):
    await _job_runtime_queue_enqueue(
        state=state,
        scan_id=scan_id,
        priority=int(priority),
        job_get=_job_get,
        job_now=_job_now,
        queue_key=JOB_QUEUE_KEY,
        refresh_queue_backlog_metric_fn=_refresh_queue_backlog_metric,
        enqueue_job_memory_fn=_enqueue_job_memory,
    )

async def _enqueue_queued_jobs():
    # Best-effort: load queued jobs to queue backend.
    if _pg_enabled():
        try:
            queued_ids = PG_STORE.list_job_ids_by_status("queued")
        except Exception as e:
            logger.warning(f"PostgreSQL queue sync failed, falling back to SQLite: {e}")
            queued_ids = []
    else:
        queued_ids = _jobs_sqlite_list_queued_job_ids(JOBS_DB_PATH)

    for scan_id in queued_ids:
        try:
            job = _job_get(str(scan_id)) or {}
            await _queue_enqueue(str(scan_id), priority=int(job.get("priority") or 0))
        except Exception:
            continue

def _enqueue_job_memory(scan_id: str):
    _job_runtime_enqueue_job_memory(state=state, queue_backlog_metric=QUEUE_BACKLOG, scan_id=scan_id)

async def _queue_pop(timeout_seconds: int = 2) -> Optional[str]:
    return await _job_runtime_queue_pop(
        state=state,
        timeout_seconds=int(timeout_seconds),
        queue_key=JOB_QUEUE_KEY,
        queue_backlog_metric=QUEUE_BACKLOG,
        refresh_queue_backlog_metric_fn=_refresh_queue_backlog_metric,
    )

async def _queue_reconciler_loop():
    await _job_runtime_queue_reconciler_loop(
        reconcile_seconds=JOB_QUEUE_RECONCILE_SECONDS,
        enqueue_queued_jobs_fn=_enqueue_queued_jobs,
    )

def _task_runtime_state(task: Optional[asyncio.Task]) -> dict:
    return _job_runtime_task_runtime_state(task)

async def _ensure_job_background_tasks(force: bool = False) -> List[str]:
    return await _job_runtime_ensure_job_background_tasks(
        state=state,
        embedded_job_worker=EMBEDDED_JOB_WORKER,
        force=bool(force),
        job_worker_loop_fn=_job_worker_loop,
        queue_reconciler_loop_fn=_queue_reconciler_loop,
    )

async def run_standalone_job_worker(stop_event: Optional[asyncio.Event] = None):
    await _worker_runner_run_standalone_worker(
        state=state,
        logger=logger,
        worker_id=WORKER_ID,
        job_queue_backend=JOB_QUEUE_BACKEND,
        stop_event=stop_event,
        init_audit_db_fn=_init_audit_db,
        init_jobs_db_fn=_init_jobs_db,
        init_job_queue_backend_fn=_init_job_queue_backend,
        jobs_recover_on_startup_fn=_jobs_recover_on_startup,
        enqueue_queued_jobs_fn=_enqueue_queued_jobs,
        ensure_job_background_tasks_fn=_ensure_job_background_tasks,
    )

def _payload_for_user_id(user_id: str) -> JWTPayload:
    return _worker_identity_build_worker_payload(
        user_id=str(user_id),
        users=state.users,
        role_admin=Role.ADMIN,
        role_permissions=ROLE_PERMISSIONS,
        token_type_access=TokenType.ACCESS,
        jwt_payload_cls=JWTPayload,
        access_token_expire_minutes=SecurityConfig.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    )

async def _job_worker_loop():
    async def _queue_pop_bridge(timeout_seconds: int) -> Optional[str]:
        return await _queue_pop(timeout_seconds=timeout_seconds)

    await _job_worker_worker_loop(
        state=state,
        queue_pop_fn=_queue_pop_bridge,
        job_get=_job_get,
        normalize_job_kind=_normalize_job_kind,
        job_update=_job_update,
        job_now=_job_now,
        worker_id=WORKER_ID,
        run_job_by_kind_fn=_run_job_by_kind,
        heartbeat_loop_fn=_job_heartbeat_loop,
    )


def _normalize_classic_to_unified_cfg(cfg: dict) -> dict:
    return _job_cfg_normalize_classic_to_unified_cfg(cfg)


def _normalize_unified_job_cfg(kind: str, cfg: dict) -> dict:
    return _job_cfg_normalize_unified_job_cfg(kind, cfg, CANONICAL_JOB_KIND)


def _validate_unified_target_policy(mode: str, cfg: dict, user_id: str) -> None:
    _target_policy_validate_unified_target_policy(
        mode=str(mode or "").lower(),
        cfg=cfg,
        user_id=str(user_id),
        payload_for_user_id_fn=_payload_for_user_id,
        read_unified_runtime_cfg_fn=_read_unified_runtime_cfg,
        policy_engine=get_policy_engine(),
        action_type_scan=ActionType.SCAN,
        validate_target_fn=validate_target,
        validate_network_host_fn=validate_network_host,
    )


def _unified_multilevel_job_deps() -> UnifiedMultilevelJobDeps:
    # Contract marker for route-surface tests: runtime sequence keeps OrchestratorPhase.ESCALATION.
    return UnifiedMultilevelJobDeps(
        state=state,
        logger=logger,
        canonical_job_kind=CANONICAL_JOB_KIND,
        normalize_job_kind_fn=_normalize_job_kind,
        normalize_unified_job_cfg_fn=_normalize_unified_job_cfg,
        apply_autopilot_policy_fn=_apply_autopilot_policy,
        validate_unified_target_policy_fn=_validate_unified_target_policy,
        read_unified_runtime_cfg_fn=_read_unified_runtime_cfg,
        run_omni_surface_scan_fn=run_omni_surface_scan,
        get_policy_engine_fn=get_policy_engine,
        action_type=ActionType,
        orchestrator_cls=Orchestrator,
        orchestrator_phase=OrchestratorPhase,
        broadcast_log_fn=broadcast_log,
        job_update_fn=_job_update,
        job_now_fn=_job_now,
        job_get_fn=_job_get,
        history_dir=HISTORY_DIR,
    )


async def _run_unified_multilevel_job(scan_id: str, user_id: str, kind: str, cfg: dict) -> None:
    await _run_unified_multilevel_job_impl(scan_id, user_id, kind, cfg, _unified_multilevel_job_deps())

async def _run_job_by_kind(scan_id: str, user_id: str, kind: str, cfg: dict) -> None:
    await _run_unified_multilevel_job(scan_id, user_id, kind, cfg)

async def _job_heartbeat_loop(scan_id: str):
    await _job_worker_heartbeat_loop(
        scan_id=scan_id,
        heartbeat_seconds=JOB_HEARTBEAT_SECONDS,
        worker_id=WORKER_ID,
        job_get=_job_get,
        job_update=_job_update,
        job_now=_job_now,
    )


def _start_sqlmap_process(cmd: List[str]) -> subprocess.Popen:
    return _process_guard_start_sqlmap_process(
        cmd,
        rlimit_cpu_seconds=SCAN_RLIMIT_CPU_SECONDS,
        rlimit_as_mb=SCAN_RLIMIT_AS_MB,
    )

def _terminate_process_tree(proc: Optional[subprocess.Popen]):
    _process_guard_terminate_process_tree(proc)

def _normalize_host(host: str) -> str:
    return _process_guard_normalize_host(host)

def _is_ip(value: str) -> bool:
    return _process_guard_is_ip(value)

def _host_allowed(host: str) -> bool:
    return _process_guard_host_allowed(host, ALLOWED_TARGETS)

def _target_slug(url: str) -> str:
    return _scan_utils_target_slug(url)

def _safe_history_path(filename: str) -> str:
    return _scan_utils_safe_history_path(HISTORY_DIR, filename)

def _init_audit_db():
    _audit_store_init_audit_db(AUDIT_DB_PATH)


def _init_jobs_db():
    if _pg_enabled():
        try:
            PG_STORE.ensure_schema()
            logger.info("🗄️ PostgreSQL schema ready (jobs/scans/ledgers/verdicts)")
            return
        except Exception as e:
            logger.warning(f"PostgreSQL init failed, falling back to SQLite: {e}")
    _jobs_sqlite_init_jobs_db(JOBS_DB_PATH)


def _job_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _job_persistence_runtime_deps() -> JobPersistenceRuntimeDeps:
    return JobPersistenceRuntimeDeps(
        pg_enabled_fn=_pg_enabled,
        pg_store=PG_STORE,
        jobs_db_path=JOBS_DB_PATH,
        normalize_job_kind_fn=_normalize_job_kind,
        normalize_unified_scan_cfg_fn=_normalize_unified_scan_cfg,
        read_unified_runtime_cfg_fn=_read_unified_runtime_cfg,
        persist_scan_artifacts_db_fn=_persist_scan_artifacts_db,
        sqlite_create_job_fn=_jobs_sqlite_create_job,
        sqlite_update_job_fn=_jobs_sqlite_update_job,
        sqlite_get_job_fn=_jobs_sqlite_get_job,
        sqlite_list_jobs_fn=_jobs_sqlite_list_jobs,
        build_default_vector_page_fn=_build_default_vector_page,
        logger=logger,
    )


def _job_create(*, scan_id: str, user_id: str, kind: str, status: str, phase: int, max_phase: int, autopilot: bool, target_url: str, cfg: dict, pid: Optional[int] = None, priority: int = 0):
    _job_persist_create_job_impl(
        scan_id=scan_id,
        user_id=user_id,
        kind=kind,
        status=status,
        phase=int(phase),
        max_phase=int(max_phase),
        autopilot=bool(autopilot),
        target_url=str(target_url),
        cfg=(cfg or {}),
        pid=pid,
        priority=int(priority),
        deps=_job_persistence_runtime_deps(),
        job_now_fn=_job_now,
    )


def _job_update(scan_id: str, **fields):
    _job_persist_update_job_impl(
        scan_id=str(scan_id),
        deps=_job_persistence_runtime_deps(),
        fields=(fields or {}),
    )


def _job_get(scan_id: str) -> Optional[dict]:
    return _job_persist_get_job_impl(str(scan_id), deps=_job_persistence_runtime_deps())


def _job_list(user_id: str, limit: int = 30) -> List[dict]:
    return _job_persist_list_jobs_impl(str(user_id), limit=int(limit), deps=_job_persistence_runtime_deps())


def _fallback_coverage_response_from_job(job: Dict[str, Any], scan_id: str, *, limit: int, cursor: int) -> CoverageResponseV1:
    return _job_persist_fallback_coverage_response_from_job_impl(
        job=job,
        scan_id=str(scan_id),
        limit=int(limit),
        cursor=int(cursor),
        deps=_job_persistence_runtime_deps(),
    )


def _job_get_coverage_v1(scan_id: str, *, limit: int, cursor: int) -> Optional[CoverageResponseV1]:
    return _job_persist_get_job_coverage_v1_impl(
        str(scan_id),
        limit=int(limit),
        cursor=int(cursor),
        deps=_job_persistence_runtime_deps(),
    )


def _append_audit_chain(log_entry: AuditLog):
    _audit_store_append_audit_chain(AUDIT_DB_PATH, log_entry)

def _verify_audit_chain() -> dict:
    return _audit_store_verify_audit_chain(AUDIT_DB_PATH)

app = FastAPI(
    title="Cerberus Pro API",
    description="Backend de Orquestación de Seguridad Avanzada y Evasión WAF",
    version="3.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "Cerberus Security Team",
        "email": "security@cerberus.corp",
    }
)

# Add middleware (order matters!)
app.add_middleware(SecurityHeadersMiddleware)
app.state.limiter = limiter
if RATE_LIMIT_ENABLED and _SLOWAPI_AVAILABLE:
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    TrustedHostMiddleware,
    # Include explicit host:port entries used by the Vite dev server to avoid
    # Host header rejections during WebSocket upgrade in development.
    allowed_hosts=(
        [
            "localhost",
            "127.0.0.1",
            "localhost:8001",
            "127.0.0.1:8001",
            "localhost:5173",
            "127.0.0.1:5173",
            "localhost:5178",
            "127.0.0.1:5178"
        ]
        if ENVIRONMENT == 'development'
        else ["*.cerberus.local"]
    )
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5178", "http://127.0.0.1:5178", "http://localhost:8001", "http://127.0.0.1:8001"]
        if ENVIRONMENT == 'development'
        else ["https://*.cerberus.local"]
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

# Reuse modular verdict endpoints in the secure runtime app.
app.include_router(verdicts_router, prefix="/verdict", tags=["verdict"])
app.include_router(engines_router, prefix="/engines", tags=["engines"])

# Auth router (extracted from monolith)
from routers.auth import router as auth_router
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# Admin router (extracted from monolith)
from routers.admin import router as admin_router
app.include_router(admin_router, prefix="/admin", tags=["admin"])
# API Keys share /auth prefix
app.include_router(admin_router, prefix="/auth", tags=["api-keys"], include_in_schema=False)

# [AUTH ENDPOINTS EXTRACTED TO routers/auth.py]

# [USER MANAGEMENT + API KEY ENDPOINTS EXTRACTED TO routers/admin.py]


# ============================================================================
# SCANNING ENDPOINTS (SECURED)
# ============================================================================

def validate_target(url: str, user: JWTPayload) -> bool:
    return _target_validation_validate_target(
        url=url,
        user=user,
        allowed_web_schemes=ALLOWED_WEB_SCHEMES,
        allow_local_targets=ALLOW_LOCAL_TARGETS,
        environment=ENVIRONMENT,
        allowed_targets=ALLOWED_TARGETS,
        validate_redirect_chain=VALIDATE_REDIRECT_CHAIN,
        host_allowed_fn=_host_allowed,
        resolve_and_validate_fn=lambda target, allow_private: DNSValidator.resolve_and_validate(
            target, allow_private=allow_private
        ),
        logger=logger,
    )

def validate_network_host(host: str) -> bool:
    return _target_validation_validate_network_host(
        host,
        host_allowed_fn=_host_allowed,
        resolve_and_validate_fn=lambda target, allow_private: DNSValidator.resolve_and_validate(
            target, allow_private=allow_private
        ),
    )

def sanitize_line(line: str) -> str:
    return _log_output_sanitize_line(line)

def translate_log(line: str) -> str:
    return _log_output_translate_log(line)

def _merge_tampers(current: str, incoming: List[str]) -> str:
    return _scan_utils_merge_tampers(current, incoming)


def _autopilot_difficulty(cfg: dict) -> str:
    return _scan_utils_autopilot_difficulty(cfg)


from autopilot_utils import detect_defensive_measures

def _apply_autopilot_policy(cfg: dict, mode: str, phase: int = 1) -> dict:
    return _scan_utils_apply_autopilot_policy(cfg, mode, phase)

def _validate_host_port(host: str, port: int, label: str):
    return _scan_utils_validate_host_port(host, port, label)

def validate_omni_config(cfg: dict):
    return _scan_utils_validate_omni_config(
        cfg,
        allowed_modes=OMNI_ALLOWED_MODES,
        allowed_vectors=OMNI_ALLOWED_VECTORS,
    )

async def broadcast_log(component: str, level: str, msg: str, metadata: Optional[dict] = None):
    await broadcast({
        "type": "log",
        "component": component,
        "level": level,
        "msg": msg,
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

async def run_omni_surface_scan(user_id: str, cfg: dict):
    """Phase 2+3: polymorphic evasion + multi-surface orchestration."""
    cfg = _ensure_unified_cfg_aliases(cfg or {})
    if cfg.get("autoPilot"):
        cfg = _apply_autopilot_policy(
            cfg,
            mode=(cfg.get("mode") or "web").lower(),
            phase=int(cfg.get("autoPilotPhase") or 1),
        )
    runtime_ctx = _omni_runtime_prepare_scan_context(
        cfg=cfg,
        user_id=str(user_id),
        state_omni_meta=state.omni_meta,
        allowed_vectors=OMNI_ALLOWED_VECTORS,
    )
    target_url = str(runtime_ctx.get("target_url") or "")
    sql_config = dict(runtime_ctx.get("sql_config") or {})
    mode = str(runtime_ctx.get("mode") or "web")
    omni_cfg = dict(runtime_ctx.get("omni_cfg") or {})
    max_parallel = int(runtime_ctx.get("max_parallel") or 4)
    engine_scan_enabled = bool(runtime_ctx.get("engine_scan_enabled"))
    configured_engine_list = list(runtime_ctx.get("configured_engine_list") or [])
    requested_sqlmap_vectors = [str(v).upper() for v in (runtime_ctx.get("requested_sqlmap_vectors") or [])]
    is_deep = bool(runtime_ctx.get("is_deep"))
    phases = [int(p) for p in (runtime_ctx.get("phases") or [int(cfg.get("autoPilotPhase") or 1)])]
    strict_conclusive = bool(runtime_ctx.get("strict_conclusive"))
    defended_by_default = bool(runtime_ctx.get("defended_by_default"))
    scan_id = str(runtime_ctx.get("scan_id") or "")
    scan_started_at = runtime_ctx.get("scan_started_at") or datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []
    final_vuln = False

    defended_heuristics = _omni_runtime_compute_defended_heuristics_seed(
        mode=mode,
        target_url=target_url,
        defended_by_default=defended_by_default,
        omni_cfg=omni_cfg,
    )
    if mode in ("web", "graphql") and defended_by_default:
        try:
            http_heuristics = await suspect_defended_target(target_url)
            defended_heuristics = _omni_runtime_merge_defended_heuristics(
                defended_heuristics, http_heuristics
            )
            if defended_heuristics.get("suspected"):
                await broadcast_log(
                    "ORQUESTADOR",
                    "INFO",
                    f"Defended-by-default: señales heurísticas detectadas {defended_heuristics.get('reasons')}",
                    {"reasons": defended_heuristics.get("reasons")},
                )
        except Exception:
            defended_heuristics = {"suspected": False, "reasons": []}

    deduped_requested_engines = _omni_runtime_build_requested_engines(
        mode=mode,
        requested_sqlmap_vectors=requested_sqlmap_vectors,
        omni_cfg=omni_cfg,
        engine_scan_enabled=engine_scan_enabled,
        configured_engine_list=configured_engine_list,
    )

    coverage_ledger = CoverageLedger(
        scan_id=scan_id,
        target_url=(target_url or mode or "unknown"),
        budget_max_time_ms=max(1000, int(SCAN_TIMEOUT_TOTAL_SECONDS) * 1000),
        budget_max_retries=max(1, len(phases)),
        budget_max_parallel=max(1, max_parallel),
        budget_max_phase_time_ms=max(1000, int((SCAN_TIMEOUT_TOTAL_SECONDS * 1000) / max(1, len(phases)))),
        engines_requested=deduped_requested_engines,
    )
    coverage_ledger.vectors_requested = {eng: [eng] for eng in deduped_requested_engines}

    orchestrator = Orchestrator(scan_id=scan_id, target_url=(target_url or mode or "unknown"))
    phases_ran: List[int] = []
    waf_preset_last: Optional[str] = None
    bypass_attempted = False
    bypass_cookie_obtained = False
    persisted_cookie_header = str(
        ((state.omni_meta.get(user_id) or {}).get("session_cookie") or "")
    ).strip()
    preflight_summary: Dict[str, Any] = {
        "ok": True,
        "checked": [],
        "missing": [],
        "executed": [],
    }

    async def _mark_phase(phase: OrchestratorPhase, note: str, status: str = "completed") -> None:
        try:
            coverage_ledger.add_phase_record(
                PhaseCompletionRecord(
                    phase=str(phase.value if hasattr(phase, "value") else phase),
                    status=str(status),
                    duration_ms=0,
                    start_time=datetime.now(timezone.utc),
                    end_time=datetime.now(timezone.utc),
                    items_processed=0,
                    items_failed=0,
                    notes=[str(note)] if note else [],
                )
            )
        except Exception:
            pass

    async def _run_registered_engines_unified() -> None:
        nonlocal final_vuln, preflight_summary

        def _inc_preflight_fail(dep: str) -> None:
            try:
                PREFLIGHT_FAIL_TOTAL.labels(dependency=str(dep)).inc()
            except Exception:
                pass

        found = await _omni_engine_run_registered_engines_unified(
            target_url=target_url,
            omni_cfg=omni_cfg,
            configured_engine_list=configured_engine_list,
            results=results,
            coverage_ledger=coverage_ledger,
            preflight_summary=preflight_summary,
            build_engine_vectors_for_target_fn=_omni_runtime_build_engine_vectors_for_target,
            broadcast_log_fn=broadcast_log,
            conclusive_blocker_cls=ConclusiveBlocker,
            preflight_fail_inc_fn=_inc_preflight_fail,
        )
        final_vuln = bool(final_vuln or found)

    if mode in ("web", "graphql"):
        web_exec = await _omni_web_execute_mode_phases(
            user_id=str(user_id),
            cfg=cfg,
            target_url=str(target_url),
            sql_config=dict(sql_config or {}),
            omni_cfg=dict(omni_cfg or {}),
            max_parallel=int(max_parallel),
            requested_sqlmap_vectors=[str(v).upper() for v in requested_sqlmap_vectors],
            phases=[int(p) for p in phases],
            is_deep=bool(is_deep),
            defended_heuristics=dict(defended_heuristics or {}),
            persisted_cookie_header=str(persisted_cookie_header or ""),
            state_omni_meta=state.omni_meta,
            python_exec=(sys.executable or "python"),
            sqlmap_path=SQLMAP_PATH,
            calibration_waf_detect_fn=calibration_waf_detect,
            polymorphic_evasion_cls=PolymorphicEvasionEngine,
            differential_validator_cls=DifferentialResponseValidator,
            browser_stealth_cls=BrowserStealth,
            build_vector_commands_fn=build_vector_commands,
            run_sqlmap_vector_fn=run_sqlmap_vector,
            broadcast_log_fn=broadcast_log,
            engine_registry=engine_registry,
        )
        results = list(web_exec.get("results") or [])
        phases_ran = [int(p) for p in (web_exec.get("phases_ran") or [])]
        final_vuln = bool(web_exec.get("final_vuln"))
        waf_preset_last = (
            str(web_exec.get("waf_preset_last"))
            if web_exec.get("waf_preset_last") is not None
            else None
        )
        bypass_attempted = bool(web_exec.get("bypass_attempted"))
        bypass_cookie_obtained = bool(web_exec.get("bypass_cookie_obtained"))
        persisted_cookie_header = str(web_exec.get("persisted_cookie_header") or "")
        if engine_scan_enabled:
            await _run_registered_engines_unified()
    else:
        def _inc_preflight_fail_nonweb(dep: str) -> None:
            try:
                PREFLIGHT_FAIL_TOTAL.labels(dependency=str(dep)).inc()
            except Exception:
                pass

        nonweb_exec = await _omni_nonweb_execute_mode(
            mode=mode,
            cfg=cfg,
            omni_cfg=omni_cfg,
            results=results,
            final_vuln=bool(final_vuln),
            preflight_summary=preflight_summary,
            coverage_ledger=coverage_ledger,
            execution_phase=OrchestratorPhase.EXECUTION,
            mark_phase_fn=_mark_phase,
            preflight_fail_inc_fn=_inc_preflight_fail_nonweb,
            direct_db_reachability_fn=direct_db_reachability,
            websocket_exploit_fn=websocket_exploit,
            mqtt_exploit_fn=mqtt_exploit,
            grpc_deep_fuzz_probe_fn=grpc_deep_fuzz_probe,
        )
        results = list(nonweb_exec.get("results") or results)
        final_vuln = bool(nonweb_exec.get("final_vuln"))
        for phase_id in (nonweb_exec.get("phases_ran") or []):
            phases_ran.append(int(phase_id))
        preflight_summary = dict(nonweb_exec.get("preflight_summary") or preflight_summary)

    # Fill executed_vectors for coverage report
    executed_vectors = list(set([r.get("vector", "UNKNOWN") for r in results]))
    
    # Log progress to state for UI polling compatibility
    if user_id in state.omni_meta:
        state.omni_meta[user_id]["completed_vectors"] = len(results)
        state.omni_meta[user_id]["total_vectors"] = len(results)
        state.omni_meta[user_id]["last_message"] = "Orquestación sincronizada completada."

    # Skip legacy loop as we already have synchronized results

    # Final Report Generation (outside phase loop)
    if not scan_id:
        scan_id = str((state.omni_meta.get(user_id) or {}).get("scan_id") or "")
    analysis = _omni_runtime_analyze_results_for_verdict(
        results=results,
        requested_sqlmap_vectors=requested_sqlmap_vectors,
        omni_allowed_vectors=OMNI_ALLOWED_VECTORS,
        mode=mode,
        target_url=target_url,
        omni_cfg=omni_cfg,
        final_vuln=bool(final_vuln),
        strict_conclusive=bool(strict_conclusive),
        is_deep=bool(is_deep),
        phases_ran=phases_ran,
        phases=phases,
        waf_preset_last=waf_preset_last,
        bypass_attempted=bool(bypass_attempted),
        bypass_cookie_obtained=bool(bypass_cookie_obtained),
        coverage_deps_missing=(coverage_ledger.deps_missing or []),
    )
    results_count = int(analysis.get("results_count") or 0)
    evidence_count = int(analysis.get("evidence_count") or 0)
    failed_vectors = [str(v) for v in (analysis.get("failed_vectors") or [])]
    exception_count = int(analysis.get("exception_count") or 0)
    present_vectors = {str(v).upper() for v in (analysis.get("present_vectors") or set())}
    missing_requested = [str(v) for v in (analysis.get("missing_requested") or [])]
    sqlmap_tested_params = set(analysis.get("sqlmap_tested_params") or set())
    sqlmap_no_forms_found = bool(analysis.get("sqlmap_no_forms_found"))
    sqlmap_missing_parameters = bool(analysis.get("sqlmap_missing_parameters"))
    sqlmap_explicit_not_injectable = bool(analysis.get("sqlmap_explicit_not_injectable"))
    inputs_tested = bool(analysis.get("inputs_tested"))
    reasons = [str(code) for code in (analysis.get("reasons") or [])]
    merged_missing_deps = [str(dep) for dep in (analysis.get("merged_missing_deps") or [])]

    for blocker in (coverage_ledger.conclusive_blockers or []):
        code = f"{blocker.category}:{blocker.detail}"
        if code not in reasons:
            reasons.append(code)

    requested_verdict = (
        "VULNERABLE"
        if final_vuln
        else ("NO_VULNERABLE" if len(reasons) == 0 else "INCONCLUSIVE")
    )

    finalized = await _omni_finalize_coverage(
        coverage_ledger=coverage_ledger,
        results=results,
        executed_vectors=executed_vectors,
        present_vectors=present_vectors,
        mode=mode,
        sqlmap_tested_params=sqlmap_tested_params,
        sqlmap_explicit_not_injectable=sqlmap_explicit_not_injectable,
        failed_vectors=failed_vectors,
        merged_missing_deps=merged_missing_deps,
        phases_ran=phases_ran,
        reasons=reasons,
        scan_started_at=scan_started_at,
        deduped_requested_engines=deduped_requested_engines,
        preflight_summary=preflight_summary,
        exception_count=exception_count,
        final_vuln=bool(final_vuln),
        requested_verdict=requested_verdict,
        scan_id=str(scan_id or ""),
        orchestrator=orchestrator,
        mark_phase_fn=_mark_phase,
        verdict_phase=OrchestratorPhase.VERDICT,
    )
    coverage_response = finalized["coverage_response"]
    verdict = str(finalized["verdict"])
    conclusive = bool(finalized["conclusive"])
    final_vuln = bool(finalized["final_vuln"])
    msg = str(finalized["msg"])
    orchestrator_report = finalized["orchestrator_report"]

    coverage = {
        "kind": CANONICAL_JOB_KIND,
        "scan_id": scan_id or None,
        "mode": mode,
        "strict_conclusive": strict_conclusive,
        "deep_audit": is_deep,
        "phases_requested": phases,
        "phases_ran": phases_ran,
        "vectors_requested": requested_sqlmap_vectors,
        "missing_vectors": missing_requested,
        "failed_vectors": sorted(list(set(failed_vectors)))[:50],
        "missing_dependencies": merged_missing_deps[:50],
        "preflight_dependencies": preflight_summary,
        "tested_parameters_count": len(sqlmap_tested_params),
        "tested_parameters": sorted(list(sqlmap_tested_params))[:50],
        "explicit_not_injectable": bool(sqlmap_explicit_not_injectable),
        "no_forms_found": bool(sqlmap_no_forms_found),
        "missing_parameters": bool(sqlmap_missing_parameters),
        "inputs_tested": bool(inputs_tested),
        "waf_preset": waf_preset_last,
        "bypass_attempted": bypass_attempted,
        "bypass_cookie_obtained": bypass_cookie_obtained,
        "conclusive_blockers": [b.model_dump() for b in coverage_response.conclusive_blockers],
        "conclusive_blockers_legacy": reasons,
        "orchestrator": orchestrator_report,
        "ledger": {
            "coverage_percentage": coverage_ledger.coverage_percentage(),
            "engines_requested": coverage_ledger.engines_requested,
            "engines_executed": coverage_ledger.engines_executed,
            "inputs_found": coverage_ledger.inputs_found,
            "inputs_tested": coverage_ledger.inputs_tested,
            "inputs_failed": coverage_ledger.inputs_failed,
            "deps_missing": coverage_ledger.deps_missing,
            "status": coverage_ledger.status,
            "total_duration_ms": coverage_ledger.total_duration_ms,
        },
        **_coverage_public_payload(coverage_response, legacy_reason_codes=reasons),
    }
    _emit_verdict_metrics(verdict, coverage_response.conclusive_blockers)
    _record_phase_durations_from_coverage(coverage)
    _record_job_duration(CANONICAL_JOB_KIND, coverage)

    report = {
        "type": "report",
        "mode": mode,
        "vulnerable": final_vuln,
        "count": len(results),
        "msg": "AUDITORÍA PROFUNDA COMPLETADA" if is_deep else f"OMNI {mode.upper()} COMPLETADO",
        "data": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "intelligence": {
            "is_deep": is_deep,
            "max_phase": (max(phases_ran) if phases_ran else int(cfg.get("autoPilotPhase") or 1))
        }
    }
    report.update({
        "kind": CANONICAL_JOB_KIND,
        "scan_id": scan_id,
        "verdict": verdict,
        "conclusive": conclusive,
        "results_count": results_count,
        "evidence_count": evidence_count,
        "coverage": coverage,
    })
    report["msg"] = msg
    await broadcast(report)
    await broadcast_log("ORQUESTADOR", "SUCCESS", "Auditoría finalizada" if is_deep else "Escaneo finalizado")
    state.omni_meta[user_id]["current_vector"] = None
    state.omni_meta[user_id]["last_message"] = "completed"

    # PERSISTENCE: Save report to history + update job row (if any).
    try:
        filename, filepath, history_timestamp = _omni_history_make_history_paths(
            scan_id=str(scan_id or ""),
            target_url=str(target_url or ""),
            mode=str(mode),
            history_dir=HISTORY_DIR,
            target_slug_fn=_target_slug,
            now=datetime.now(timezone.utc),
        )
        history_data = _omni_history_build_history_data(
            filename=filename,
            timestamp_iso=history_timestamp,
            target=(target_url or mode),
            mode=str(mode),
            profile=cfg.get("profile"),
            vulnerable=bool(final_vuln),
            verdict=str(verdict),
            conclusive=bool(conclusive),
            count=int(results_count),
            data=list(results or []),
            coverage=dict(coverage or {}),
            config=dict(cfg or {}),
        )
        _omni_history_set_evidence_count(history_data, evidence_count)

        # Attempt to synthesize structured findings (PoC, confidence, dbms) from raw engine results
        try:
            structured = synthesize_structured_findings(target_url or mode, results or [])
            history_data["structured_findings"] = structured
        except Exception as synth_err:
            history_data["structured_findings_error"] = str(synth_err)

        _persist_scan_artifacts_db(
            scan_id=str(scan_id or ""),
            user_id=str(user_id),
            kind=CANONICAL_JOB_KIND,
            target_url=str(target_url or mode or ""),
            mode=str(mode),
            profile=(str(cfg.get("profile")) if cfg.get("profile") is not None else None),
            status="completed",
            verdict=verdict,
            conclusive=bool(conclusive),
            vulnerable=bool(final_vuln),
            count=int(results_count),
            evidence_count=int(evidence_count),
            results_count=int(results_count),
            message=msg,
            cfg=cfg,
            coverage=coverage,
            report_data=history_data,
        )
        _persist_coverage_v1_db(coverage_response)

        _omni_history_persist_history_json(
            filepath=filepath,
            filename=filename,
            history_data=history_data,
            store_plain=bool(HISTORY_STORE_PLAIN),
        )

        try:
            from encryption import encrypt_report, get_encryption_key
            encrypted_file = _omni_history_persist_encrypted_artifact(
                filepath=filepath,
                history_data=history_data,
                encrypt_report_fn=encrypt_report,
                get_encryption_key_fn=get_encryption_key,
            )
            logger.info(f"🔐 Encrypted report saved: {encrypted_file}")
        except Exception as enc_err:
            logger.warning(f"⚠️ Encryption failed: {enc_err}")

        logger.info(f"💾 Omni scan guardado en historial: {filename}")

        # Update job row if this run is worker-owned.
        if scan_id:
            job_vulnerable = (1 if verdict == "VULNERABLE" else (0 if verdict == "NO_VULNERABLE" else None))
            _job_update(
                scan_id,
                status="completed",
                finished_at=_job_now(),
                result_filename=filename,
                vulnerable=job_vulnerable,
                error=None,
            )
        return {
            "scan_id": scan_id,
            "verdict": verdict,
            "conclusive": bool(conclusive),
            "vulnerable": bool(final_vuln),
            "coverage": coverage,
            "data": results,
            "results_count": int(results_count),
            "evidence_count": int(evidence_count),
        }
    except Exception as exc:
        if user_id in state.omni_meta:
            state.omni_meta[user_id]["last_error"] = str(exc)
            state.omni_meta[user_id]["last_message"] = "error"
        if scan_id:
            _job_update(scan_id, status="failed", finished_at=_job_now(), error=str(exc))
        return {
            "scan_id": scan_id,
            "verdict": "INCONCLUSIVE",
            "conclusive": False,
            "vulnerable": False,
            "coverage": {},
            "data": [],
            "results_count": 0,
            "evidence_count": 0,
            "error": str(exc),
        }

def _pending_jobs_count(user_id: str) -> int:
    return _job_count_db(user_id=str(user_id), statuses=["queued", "running"])

def _default_unified_vectors_from_cfg(cfg: dict) -> List[str]:
    return _scan_utils_default_unified_vectors_from_cfg(cfg, allowed_vectors=OMNI_ALLOWED_VECTORS)


def _normalize_unified_scan_cfg(raw_cfg: dict) -> dict:
    return _scan_utils_normalize_unified_scan_cfg(raw_cfg, allowed_vectors=OMNI_ALLOWED_VECTORS)


async def _queue_unified_scan(request: Request, current_user: JWTPayload, *, source_endpoint: str) -> dict:
    body = await request.json()
    raw_cfg = body.get("config", {}) or {}
    if "unified" not in raw_cfg and "omni" in raw_cfg:
        raise HTTPException(status_code=400, detail="Hard break activo: usa config.unified (config.omni no soportado)")
    cfg = _normalize_unified_scan_cfg(raw_cfg)
    target_url = str(cfg.get("url", "") or "")
    mode = validate_omni_config(cfg)
    unified_cfg = _read_unified_runtime_cfg(cfg)

    if mode in ("web", "graphql") and not validate_target(target_url, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target not allowed or is private IP"
        )
    if mode == "direct_db":
        db_cfg = (unified_cfg.get("directDb", {}) or {})
        if not validate_network_host(str(db_cfg.get("host", ""))):
            raise HTTPException(status_code=403, detail="Direct DB host blocked by policy")
    if mode == "ws":
        ws_url = str(unified_cfg.get("wsUrl", ""))
        ws_host = urlparse(ws_url).hostname or ""
        if not ws_host or not validate_network_host(ws_host):
            raise HTTPException(status_code=403, detail="WebSocket host blocked by policy")
    if mode == "mqtt":
        mqtt_host = str((unified_cfg.get("mqtt", {}) or {}).get("host", ""))
        if not validate_network_host(mqtt_host):
            raise HTTPException(status_code=403, detail="MQTT host blocked by policy")
    if mode == "grpc":
        grpc_host = str((unified_cfg.get("grpc", {}) or {}).get("host", ""))
        if not validate_network_host(grpc_host):
            raise HTTPException(status_code=403, detail="gRPC host blocked by policy")

    max_pending = int(os.environ.get("MAX_PENDING_JOBS_PER_USER", "3"))
    if _pending_jobs_count(current_user.sub) >= max_pending:
        raise HTTPException(status_code=409, detail=f"Too many pending jobs (limit={max_pending})")

    scan_id = secrets.token_urlsafe(12)
    _job_create(
        scan_id=scan_id,
        user_id=current_user.sub,
        kind=CANONICAL_JOB_KIND,
        status="queued",
        phase=int(cfg.get("autoPilotPhase") or 1),
        max_phase=AUTOPILOT_MAX_PHASE,
        autopilot=bool(cfg.get("autoPilot")),
        target_url=target_url or mode,
        cfg=cfg,
        pid=None,
        priority=int(cfg.get("priority") or 0),
    )
    await _queue_enqueue(scan_id, priority=int(cfg.get("priority") or 0))
    await _ensure_job_background_tasks()
    SCAN_START_TOTAL.labels(kind=CANONICAL_JOB_KIND).inc()

    logger.info(f"🧾 Unified job queued by {current_user.username} scan_id={scan_id} mode={mode} source={source_endpoint}")
    await audit_log(
        user_id=current_user.sub,
        action="scan_unified_queued",
        resource_type="scan",
        resource_id=scan_id,
        after={"mode": mode, "url": target_url, "kind": CANONICAL_JOB_KIND, "source_endpoint": source_endpoint, "config": cfg},
        status="success"
    )

    return {
        "message": "Unified job queued",
        "mode": mode,
        "scan_id": scan_id,
        "status": "queued",
        "kind": "unified",
        "canonical_endpoint": "/scan/start",
        "source_endpoint": source_endpoint,
    }


@app.post("/scan/start")
@limiter.limit("20/minute")
async def start_scan(
    request: Request,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_CREATE))
):
    """Canonical unified scan start endpoint."""
    return await _queue_unified_scan(request, current_user, source_endpoint="/scan/start")


def _scan_capabilities_payload() -> Dict[str, Any]:
    return {
        "modes": sorted(list(OMNI_ALLOWED_MODES)),
        "vectors": sorted(list(OMNI_ALLOWED_VECTORS)),
        "limits": {
            "max_parallel_min": 1,
            "max_parallel_max": 8
        },
        "notes": {
            "grpc": "Deep fuzzing active (Reflection + Discovery)",
            "nosql": "MongoDB & Redis injection patterns",
            "evasion_2026": "Cloudflare/Akamai/AWS specific presets active",
            "ssti": "Template injection probes (Jinja2, Twig, etc.)",
            "oob": "DNS/ICMP tunneling implemented via sqlmap backend",
            "pivoting": "Tor & Proxy support active",
            "chaining": "Automatic environment extraction after confirmed vuln"
        }
    }


@app.get("/scan/capabilities")
async def scan_capabilities(current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    return _scan_capabilities_payload()

@app.get("/metrics")
async def metrics(current_user: JWTPayload = Depends(require_permission(Permission.ADMIN_AUDIT))):
    worker_based = sum(1 for k in state.running_kind_by_user.values() if _normalize_job_kind(k) == CANONICAL_JOB_KIND)
    ACTIVE_OMNI_SCANS.set(int(worker_based))
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/setup/playwright")
@limiter.limit("5/minute")
async def setup_playwright(
    request: Request,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_CREATE))
):
    """Trigger manual browser installation for Playwright/Omni-Surface."""
    from v4_omni_surface import BrowserStealth
    logger.info(f"🛠️ Playwright setup triggered by {current_user.username}")
    success = await BrowserStealth.ensure_browsers()
    if success:
        return {"message": "Navegadores instalados exitosamente"}
    else:
        raise HTTPException(status_code=500, detail="Fallo en la instalacion de navegadores")

def _cleanup_classic_scan_runtime(user_id: str) -> None:
    state.active_scans.pop(user_id, None)
    watchdog = state.scan_watchdogs.pop(user_id, None)
    if watchdog and not watchdog.done():
        watchdog.cancel()




def _scan_stop_metric_inc(kind: str) -> None:
    SCAN_STOP_TOTAL.labels(kind=str(kind or "unknown")).inc()


def _job_control_runtime_deps() -> JobControlRuntimeDeps:
    return JobControlRuntimeDeps(
        state=state,
        canonical_job_kind=CANONICAL_JOB_KIND,
        autopilot_max_phase=AUTOPILOT_MAX_PHASE,
        normalize_job_kind_fn=_normalize_job_kind,
        job_latest_active_scan_id_fn=_job_latest_active_scan_id,
        job_list_fn=_job_list,
        job_get_fn=_job_get,
        job_get_coverage_v1_fn=_job_get_coverage_v1,
        fallback_coverage_response_from_job_fn=_fallback_coverage_response_from_job,
        job_update_fn=_job_update,
        job_now_fn=_job_now,
        terminate_process_tree_fn=_terminate_process_tree,
        normalize_unified_scan_cfg_fn=_normalize_unified_scan_cfg,
        validate_omni_config_fn=validate_omni_config,
        validate_target_fn=validate_target,
        job_create_fn=_job_create,
        queue_enqueue_fn=_queue_enqueue,
        audit_log_fn=audit_log,
        stop_metric_inc_fn=_scan_stop_metric_inc,
        cleanup_scan_runtime_fn=_cleanup_classic_scan_runtime,
    )


@app.post("/scan/stop")
@limiter.limit("30/minute")
async def stop_scan(
    request: Request,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_MODIFY)),
):
    """Stop current unified scan."""
    return await _job_control_stop_scan_payload_impl(
        current_user_sub=str(current_user.sub),
        deps=_job_control_runtime_deps(),
    )


# History router (extracted from monolith)
from routers.history import router as history_router
app.include_router(history_router, prefix="/history", tags=["history"])
# [HISTORY ENDPOINTS EXTRACTED TO routers/history.py]


@app.get("/scan/status")
async def get_scan_status(current_user: JWTPayload = Depends(get_current_user)):
    """Get unified scan status."""
    return _job_control_get_scan_status_payload_impl(
        current_user_sub=str(current_user.sub),
        deps=_job_control_runtime_deps(),
    )


@app.get("/jobs")
async def list_jobs(current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    return _job_control_list_jobs_payload_impl(
        current_user_sub=str(current_user.sub),
        deps=_job_control_runtime_deps(),
    )


@app.get("/jobs/{scan_id}")
async def get_job(scan_id: str, current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    return _job_control_get_job_payload_impl(
        scan_id=str(scan_id),
        current_user_sub=str(current_user.sub),
        deps=_job_control_runtime_deps(),
    )


@app.get("/api/v1/jobs/{scan_id}/coverage", response_model=CoverageResponseV1)
async def get_job_coverage_v1(
    scan_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: int = Query(default=0, ge=0),
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ)),
):
    return _job_control_get_job_coverage_payload_impl(
        scan_id=str(scan_id),
        current_user_sub=str(current_user.sub),
        limit=int(limit),
        cursor=int(cursor),
        deps=_job_control_runtime_deps(),
    )


@app.post("/jobs/{scan_id}/stop")
async def stop_job(scan_id: str, current_user: JWTPayload = Depends(require_permission(Permission.SCAN_MODIFY))):
    return await _job_control_stop_job_payload_impl(
        scan_id=str(scan_id),
        current_user_sub=str(current_user.sub),
        deps=_job_control_runtime_deps(),
    )


@app.post("/jobs/{scan_id}/retry")
async def retry_job(scan_id: str, current_user: JWTPayload = Depends(require_permission(Permission.SCAN_CREATE))):
    return await _job_control_retry_job_payload_impl(
        scan_id=str(scan_id),
        current_user=current_user,
        deps=_job_control_runtime_deps(),
    )

# C2/Agent router (extracted from monolith)
from routers.c2 import router as c2_router
app.include_router(c2_router, prefix="/c2", tags=["c2"])
# Agent management also accessible via /auth and /admin prefixes
app.include_router(c2_router, prefix="/auth/agent", tags=["agents"], include_in_schema=False)
app.include_router(c2_router, prefix="/admin/agents", tags=["agents"], include_in_schema=False)
# [AGENT + C2 ENDPOINTS EXTRACTED TO routers/c2.py]

# Offensive router (extracted from monolith)
from routers.offensive import router as offensive_router
app.include_router(offensive_router, tags=["offensive"])
# [METASPLOIT + EXFIL + PAYLOAD + PRIVESC ENDPOINTS EXTRACTED TO routers/offensive.py]


def _websocket_runtime_deps() -> WebsocketRuntimeDeps:
    return WebsocketRuntimeDeps(
        state=state,
        logger=logger,
        jwt_manager=JWTManager,
        role_agent=Role.AGENT,
        ws_connections_metric=WS_CONNECTIONS,
        environment=ENVIRONMENT,
        ws_handshake_debug=WS_HANDSHAKE_DEBUG,
        disable_local_dev_ws=DISABLE_LOCAL_DEV_WS,
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await _ws_endpoint_impl(websocket, _websocket_runtime_deps())


async def broadcast(obj: dict):
    await _ws_broadcast_impl(obj, _websocket_runtime_deps())


@app.websocket("/ws/agent")
async def websocket_agent_endpoint(websocket: WebSocket):
    await _ws_agent_endpoint_impl(websocket, _websocket_runtime_deps())

# ============================================================================
# AUDIT LOGGING
# ============================================================================

def _audit_runtime_deps() -> AuditRuntimeDeps:
    return AuditRuntimeDeps(
        state=state,
        logger=logger,
        audit_log_cls=AuditLog,
        append_audit_chain_fn=_append_audit_chain,
        verify_audit_chain_fn=_verify_audit_chain,
    )


def _system_ops_runtime_deps() -> SystemOpsRuntimeDeps:
    return SystemOpsRuntimeDeps(
        state=state,
        environment=ENVIRONMENT,
        job_queue_backend=JOB_QUEUE_BACKEND,
        embedded_job_worker=EMBEDDED_JOB_WORKER,
        worker_id=WORKER_ID,
        version="3.1.0",
        security_label="enterprise",
        job_count_db_fn=_job_count_db,
        ensure_job_background_tasks_fn=_ensure_job_background_tasks,
        enqueue_queued_jobs_fn=_enqueue_queued_jobs,
        task_runtime_state_fn=_task_runtime_state,
    )


async def audit_log(
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    status: str = "success",
    error_message: Optional[str] = None,
):
    await _audit_runtime_log_impl(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        before=before,
        after=after,
        status=status,
        error_message=error_message,
        deps=_audit_runtime_deps(),
    )


@app.get("/admin/audit-logs")
async def get_audit_logs(
    current_user: JWTPayload = Depends(require_permission(Permission.ADMIN_AUDIT)),
    limit: int = 100,
):
    return _audit_runtime_list_logs_impl(deps=_audit_runtime_deps(), limit=limit)


@app.get("/admin/audit-chain/verify")
async def verify_audit_chain(current_user: JWTPayload = Depends(require_permission(Permission.ADMIN_AUDIT))):
    return _audit_runtime_verify_chain_impl(deps=_audit_runtime_deps())


# ============================================================================
# HEALTH & STATUS
# ============================================================================


@app.get("/status/runtime")
async def get_runtime_status(current_user: JWTPayload = Depends(get_current_user)):
    """Get canonical runtime metadata."""
    return {
        "version": "3.1.0",
        "environment": ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "worker_id": WORKER_ID,
        "features": {
            "unified": True,
            "legacy_compat": False,
        }
    }


@app.get("/health")
async def health_check():
    return await _system_ops_health_payload_impl(deps=_system_ops_runtime_deps())


@app.post("/admin/jobs/kick")
async def admin_kick_jobs(
    force_start: bool = False,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_MODIFY)),
):
    return await _system_ops_admin_kick_jobs_payload_impl(
        deps=_system_ops_runtime_deps(),
        force_start=bool(force_start),
    )


@app.get("/status")
async def get_status(current_user: JWTPayload = Depends(get_current_user)):
    return _system_ops_status_payload_impl(deps=_system_ops_runtime_deps())

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom error response"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "timestamp": datetime.now(timezone.utc).isoformat()}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 8001)),
        log_level="info",
        ssl_keyfile=os.environ.get("SSL_KEYFILE") if ENVIRONMENT == "production" else None,
        ssl_certfile=os.environ.get("SSL_CERTFILE") if ENVIRONMENT == "production" else None,
    )








