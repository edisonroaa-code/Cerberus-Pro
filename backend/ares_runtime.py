#!/usr/bin/env python3
"""
Cerberus Pro API - Secure Backend with Enterprise Authentication
Full PHASE 1 Security Implementation
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends, Query, status
from fastapi.responses import JSONResponse
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
import re
import socket
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import logging
import json
import sys
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
from backend.core.coverage_ledger import (
    CoverageLedger,
    ConclusiveBlocker,
    PhaseCompletionRecord,
)
from backend.core.coverage_contract_v1 import (
    ConclusiveBlockerV1,
    CoverageResponseV1,
)
from backend.core.coverage_mapper import (
    _build_default_vector_page as _coverage_mapper_build_default_vector_page,
    _coverage_public_payload as _coverage_mapper_public_payload,
)
from backend.core.audit_chain_store import (
    append_audit_chain as _audit_store_append_audit_chain,
    init_audit_db as _audit_store_init_audit_db,
    verify_audit_chain as _audit_store_verify_audit_chain,
)
from backend.core.job_runtime import (
    ensure_job_background_tasks as _job_runtime_ensure_job_background_tasks,
    enqueue_job_memory as _job_runtime_enqueue_job_memory,
    init_job_queue_backend as _job_runtime_init_job_queue_backend,
    queue_enqueue as _job_runtime_queue_enqueue,
    queue_pop as _job_runtime_queue_pop,
    queue_reconciler_loop as _job_runtime_queue_reconciler_loop,
    refresh_queue_backlog_metric as _job_runtime_refresh_queue_backlog_metric,
    task_runtime_state as _job_runtime_task_runtime_state,
)
from backend.core.job_worker import (
    job_heartbeat_loop as _job_worker_heartbeat_loop,
    job_worker_loop as _job_worker_worker_loop,
)
from backend.core.job_kind import (
    job_kind_candidates as _job_kind_candidates_impl,
    normalize_job_kind as _normalize_job_kind_impl,
)
from backend.core.job_config_norm import (
    normalize_unified_job_cfg as _job_cfg_normalize_unified_job_cfg,
)
from backend.core.process_guard import (
    host_allowed as _process_guard_host_allowed,
    start_sqlmap_process as _process_guard_start_sqlmap_process,
    terminate_process_tree as _process_guard_terminate_process_tree,
)
from backend.core.worker_identity import build_worker_payload as _worker_identity_build_worker_payload
from backend.core.unified_target_policy import (
    validate_unified_target_policy as _target_policy_validate_unified_target_policy,
)
from backend.core.target_validation import (
    validate_network_host as _target_validation_validate_network_host,
    validate_target as _target_validation_validate_target,
)
from backend.core.log_output import (
    sanitize_line as _log_output_sanitize_line,
    translate_log as _log_output_translate_log,
)
from backend.core.omni_scan_runtime import (
    analyze_omni_results_for_verdict as _omni_runtime_analyze_results_for_verdict,
    build_engine_vectors_for_target as _omni_runtime_build_engine_vectors_for_target,
    build_requested_engines as _omni_runtime_build_requested_engines,
    compute_defended_heuristics_seed as _omni_runtime_compute_defended_heuristics_seed,
    merge_defended_heuristics as _omni_runtime_merge_defended_heuristics,
    omni_reason_human as _omni_runtime_reason_human,
    prepare_omni_scan_context as _omni_runtime_prepare_scan_context,
)
from backend.core.omni_history import (
    build_history_data as _omni_history_build_history_data,
    make_history_paths as _omni_history_make_history_paths,
    persist_encrypted_artifact as _omni_history_persist_encrypted_artifact,
    persist_history_json as _omni_history_persist_history_json,
    set_evidence_count as _omni_history_set_evidence_count,
)
from backend.core.omni_web_execution import (
    execute_web_mode_phases as _omni_web_execute_mode_phases,
)
from backend.core.omni_engine_scan import (
    run_registered_engines_unified as _omni_engine_run_registered_engines_unified,
)
from backend.core.omni_nonweb_execution import (
    execute_nonweb_mode as _omni_nonweb_execute_mode,
)
from backend.core.omni_coverage_finalize import (
    finalize_omni_coverage as _omni_finalize_coverage,
)
from backend.core.classic_scan_runtime import (
    ClassicScanRuntimeDeps,
    scan_reader_task as _classic_scan_reader_task_impl,
    start_next_phase as _classic_start_next_phase_impl,
)
from backend.core.unified_multilevel_job import (
    UnifiedMultilevelJobDeps,
    run_unified_multilevel_job as _run_unified_multilevel_job_impl,
)
from backend.core.websocket_runtime import (
    WebsocketRuntimeDeps,
    broadcast as _ws_broadcast_impl,
    websocket_agent_endpoint as _ws_agent_endpoint_impl,
    websocket_endpoint as _ws_endpoint_impl,
)
from backend.core.audit_runtime import (
    AuditRuntimeDeps,
    audit_log as _audit_runtime_log_impl,
    list_audit_logs as _audit_runtime_list_logs_impl,
    verify_audit_chain as _audit_runtime_verify_chain_impl,
)
from backend.core.system_ops_runtime import (
    SystemOpsRuntimeDeps,
    admin_kick_jobs_payload as _system_ops_admin_kick_jobs_payload_impl,
    health_payload as _system_ops_health_payload_impl,
    status_payload as _system_ops_status_payload_impl,
)
from backend.core.job_control_runtime import (
    JobControlRuntimeDeps,
    get_job_coverage_payload as _job_control_get_job_coverage_payload_impl,
    get_job_payload as _job_control_get_job_payload_impl,
    get_scan_status_payload as _job_control_get_scan_status_payload_impl,
    list_jobs_payload as _job_control_list_jobs_payload_impl,
    retry_job_payload as _job_control_retry_job_payload_impl,
    stop_job_payload as _job_control_stop_job_payload_impl,
    stop_scan_payload as _job_control_stop_scan_payload_impl,
)
from backend.core.job_execution_runtime import (
    JobExecutionRuntimeDeps,
    run_classic_job as _job_exec_run_classic_job_impl,
    run_omni_job as _job_exec_run_omni_job_impl,
    scan_timeout_watchdog as _job_exec_scan_timeout_watchdog_impl,
)
from backend.core.job_persistence_runtime import (
    JobPersistenceRuntimeDeps,
)
from backend.core.job_persistence_facade import JobPersistenceFacade
from backend.core.unified_queue_runtime import (
    UnifiedQueueRuntimeDeps,
    queue_unified_scan as _queue_unified_scan_impl,
)
from backend.core.postgres_persistence_runtime import (
    PostgresPersistenceRuntimeDeps,
    init_jobs_db as _pg_init_jobs_db_impl,
    job_count_db as _pg_job_count_db_impl,
    job_latest_active_scan_id as _pg_job_latest_active_scan_id_impl,
    jobs_recover_on_startup as _pg_jobs_recover_on_startup_impl,
    persist_coverage_v1_db as _pg_persist_coverage_v1_db_impl,
    persist_scan_artifacts_db as _pg_persist_scan_artifacts_db_impl,
    pg_enabled as _pg_enabled_impl,
)
from backend.core.job_queue_bridge_runtime import (
    JobQueueBridgeDeps,
    enqueue_queued_jobs as _jq_enqueue_queued_jobs_impl,
    ensure_job_background_tasks as _jq_ensure_job_background_tasks_impl,
    init_job_queue_backend as _jq_init_job_queue_backend_impl,
    job_worker_loop as _jq_job_worker_loop_impl,
    queue_enqueue as _jq_queue_enqueue_impl,
    queue_pop as _jq_queue_pop_impl,
    queue_reconciler_loop as _jq_queue_reconciler_loop_impl,
    refresh_queue_backlog_metric as _jq_refresh_queue_backlog_metric_impl,
    run_standalone_job_worker as _jq_run_standalone_job_worker_impl,
    task_runtime_state as _jq_task_runtime_state_impl,
)
from backend.core.omni_surface_runtime import (
    OmniSurfaceRuntimeDeps,
    run_omni_surface_scan as _omni_surface_scan_impl,
)
from backend.core.api_surface_ops_runtime import (
    ApiSurfaceOpsDeps,
    http_exception_payload as _api_surface_http_exception_payload_impl,
    metrics_payload as _api_surface_metrics_payload_impl,
    scan_capabilities_payload as _api_surface_scan_capabilities_payload_impl,
    setup_playwright_payload as _api_surface_setup_playwright_payload_impl,
)
from backend.core.orchestrator_fsm import Orchestrator, OrchestratorPhase
from backend.core.jobs_sqlite import (
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
from backend.core.runtime_state import CerberusState
from backend.core.events import CerberusBroadcaster
from backend.core.scan_utils import (
    AUTOPILOT_MAX_PHASE,
    OMNI_ALLOWED_MODES,
    OMNI_ALLOWED_VECTORS,
    _apply_autopilot_policy as _scan_utils_apply_autopilot_policy,
    _default_unified_vectors_from_cfg as _scan_utils_default_unified_vectors_from_cfg,
    _ensure_unified_cfg_aliases as _scan_utils_ensure_unified_cfg_aliases,
    _normalize_unified_scan_cfg as _scan_utils_normalize_unified_scan_cfg,
    _read_unified_runtime_cfg as _scan_utils_read_unified_runtime_cfg,
    _safe_history_path as _scan_utils_safe_history_path,
    _target_slug as _scan_utils_target_slug,
    validate_omni_config as _scan_utils_validate_omni_config,
)
from backend.core.worker_runner import run_standalone_worker as _worker_runner_run_standalone_worker
from backend.db.postgres_store import PostgresStore
from backend.routers.verdicts import router as verdicts_router
from backend.routers.engines import router as engines_router
from backend.routers.loot import router as loot_router
from exploits.metasploit_bridge import MetasploitBridge
from backend.c2.c2_server import C2Server
from exfiltration.dns_tunnel import DNSTunnelListener
from exfiltration.icmp_exfil import ICMPListener
from backend.payloads.payload_generator import PayloadGenerator
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
APP_LOG_LEVEL = os.environ.get("APP_LOG_LEVEL", "INFO").strip().upper()
APP_LOG_LEVEL_VALUE = getattr(logging, APP_LOG_LEVEL, logging.INFO)
logger.setLevel(APP_LOG_LEVEL_VALUE)
logging.getLogger("backend").setLevel(APP_LOG_LEVEL_VALUE)
logging.getLogger("cerberus").setLevel(APP_LOG_LEVEL_VALUE)

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
LOOT_DIR = os.environ.get("LOOT_DIR", os.path.join(os.path.dirname(__file__), 'loot'))
os.makedirs(LOOT_DIR, exist_ok=True)

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
    
    # P7-05: Anti-Tamper audit verification on startup
    try:
        audit_status = _audit_runtime_verify_chain_impl(deps=_audit_runtime_deps())
        if audit_status.get("valid"):
            logger.info("🛡️ Audit chain integrity verified")
        else:
            logger.warning(f"⚠️ AUDIT CHAIN TAMPERED OR BROKEN: {audit_status.get('error')}")
    except Exception as e:
        logger.error(f"Failed to verify audit chain: {e}")

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
        import secrets
        import os
        admin_pass = os.environ.get("CERBERUS_ADMIN_PASSWORD")
        env_mode = os.environ.get("ENVIRONMENT", "production").lower()
        if not admin_pass:
            if env_mode == "production":
                logger.error("❌ CRITICAL: CERBERUS_ADMIN_PASSWORD must be set in production environment!")
                raise RuntimeError("CERBERUS_ADMIN_PASSWORD missing in production")
            else:
                admin_pass = "admin"
                logger.warning("⚠️  Running in DEV mode. Using default admin password. DO NOT USE IN PRODUCTION.")

        admin_user = User(
            id=admin_id,
            username="admin",
            email="admin@cerberus.corp",
            full_name="System Administrator",
            role=Role.SUPER_ADMIN,
            created_at=datetime.now(timezone.utc),
            last_login=None,
            password_hash=PasswordManager.hash_password(admin_pass),
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

def _postgres_persistence_runtime_deps() -> PostgresPersistenceRuntimeDeps:
    return PostgresPersistenceRuntimeDeps(
        pg_store=PG_STORE,
        jobs_db_path=JOBS_DB_PATH,
        job_running_stale_seconds=JOB_RUNNING_STALE_SECONDS,
        logger=logger,
        normalize_job_kind_fn=_normalize_job_kind,
        job_kind_candidates_fn=_job_kind_candidates,
        job_now_fn=_job_now,
        jobs_sqlite_count_jobs_fn=_jobs_sqlite_count_jobs,
        jobs_sqlite_init_jobs_db_fn=_jobs_sqlite_init_jobs_db,
        jobs_sqlite_latest_active_scan_id_fn=_jobs_sqlite_latest_active_scan_id,
        jobs_sqlite_recover_running_jobs_fn=_jobs_sqlite_recover_running_jobs_on_startup,
    )


def _pg_enabled() -> bool:
    return _pg_enabled_impl(_postgres_persistence_runtime_deps())


def _job_count_db(*, user_id: Optional[str] = None, statuses: Optional[List[str]] = None) -> int:
    return _pg_job_count_db_impl(
        _postgres_persistence_runtime_deps(),
        user_id=user_id,
        statuses=statuses,
    )


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


_read_unified_runtime_cfg = _scan_utils_read_unified_runtime_cfg
_ensure_unified_cfg_aliases = _scan_utils_ensure_unified_cfg_aliases


def _job_latest_active_scan_id(user_id: str, kind: str) -> Optional[str]:
    return _pg_job_latest_active_scan_id_impl(
        _postgres_persistence_runtime_deps(),
        user_id=user_id,
        kind=kind,
    )

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
    _pg_persist_scan_artifacts_db_impl(
        _postgres_persistence_runtime_deps(),
        scan_id=scan_id,
        user_id=user_id,
        kind=kind,
        target_url=target_url,
        mode=mode,
        profile=profile,
        status=status,
        verdict=verdict,
        conclusive=conclusive,
        vulnerable=vulnerable,
        count=count,
        evidence_count=evidence_count,
        results_count=results_count,
        message=message,
        cfg=cfg,
        coverage=coverage,
        report_data=report_data,
    )


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


_build_default_vector_page = _coverage_mapper_build_default_vector_page
_coverage_public_payload = _coverage_mapper_public_payload


def _persist_coverage_v1_db(coverage_response: CoverageResponseV1) -> None:
    _pg_persist_coverage_v1_db_impl(_postgres_persistence_runtime_deps(), coverage_response)

def _jobs_recover_on_startup():
    # If the backend restarts, any "running" job is no longer controlled.
    # For multi-instance, a different worker might still be running it, but
    # with local process execution we must fail closed.
    _pg_jobs_recover_on_startup_impl(_postgres_persistence_runtime_deps())

def _job_queue_bridge_deps() -> JobQueueBridgeDeps:
    return JobQueueBridgeDeps(
        state=state,
        logger=logger,
        worker_id=WORKER_ID,
        embedded_job_worker=EMBEDDED_JOB_WORKER,
        job_queue_backend=JOB_QUEUE_BACKEND,
        redis_available=_REDIS_AVAILABLE,
        redis_module=redis_async,
        redis_url=JOB_QUEUE_REDIS_URL,
        queue_key=JOB_QUEUE_KEY,
        queue_reconcile_seconds=JOB_QUEUE_RECONCILE_SECONDS,
        queue_backlog_metric=QUEUE_BACKLOG,
        pg_store=PG_STORE,
        jobs_db_path=JOBS_DB_PATH,
        pg_enabled_fn=_pg_enabled,
        job_count_db_fn=_job_count_db,
        job_get_fn=_job_get,
        job_now_fn=_job_now,
        job_update_fn=_job_update,
        normalize_job_kind_fn=_normalize_job_kind,
        run_job_by_kind_fn=_run_job_by_kind,
        heartbeat_loop_fn=_job_heartbeat_loop,
        init_audit_db_fn=_init_audit_db,
        init_jobs_db_fn=_init_jobs_db,
        jobs_recover_on_startup_fn=_jobs_recover_on_startup,
        jobs_sqlite_list_queued_job_ids_fn=_jobs_sqlite_list_queued_job_ids,
        runtime_init_job_queue_backend_fn=_job_runtime_init_job_queue_backend,
        runtime_refresh_queue_backlog_metric_fn=_job_runtime_refresh_queue_backlog_metric,
        runtime_queue_enqueue_fn=_job_runtime_queue_enqueue,
        runtime_enqueue_job_memory_fn=_job_runtime_enqueue_job_memory,
        runtime_queue_pop_fn=_job_runtime_queue_pop,
        runtime_queue_reconciler_loop_fn=_job_runtime_queue_reconciler_loop,
        runtime_task_runtime_state_fn=_job_runtime_task_runtime_state,
        runtime_ensure_job_background_tasks_fn=_job_runtime_ensure_job_background_tasks,
        worker_runner_run_standalone_worker_fn=_worker_runner_run_standalone_worker,
        worker_loop_impl_fn=_job_worker_worker_loop,
    )


async def _init_job_queue_backend():
    await _jq_init_job_queue_backend_impl(_job_queue_bridge_deps())


async def _refresh_queue_backlog_metric() -> None:
    await _jq_refresh_queue_backlog_metric_impl(_job_queue_bridge_deps())


async def _queue_enqueue(scan_id: str, *, priority: int = 0):
    await _jq_queue_enqueue_impl(scan_id, priority=int(priority), deps=_job_queue_bridge_deps())


async def _enqueue_queued_jobs():
    await _jq_enqueue_queued_jobs_impl(_job_queue_bridge_deps())


async def _queue_pop(timeout_seconds: int = 2) -> Optional[str]:
    return await _jq_queue_pop_impl(timeout_seconds, _job_queue_bridge_deps())


async def _queue_reconciler_loop():
    await _jq_queue_reconciler_loop_impl(_job_queue_bridge_deps())


def _task_runtime_state(task: Optional[asyncio.Task]) -> dict:
    return _jq_task_runtime_state_impl(task, _job_queue_bridge_deps())


async def _ensure_job_background_tasks(force: bool = False) -> List[str]:
    return await _jq_ensure_job_background_tasks_impl(force, _job_queue_bridge_deps())


async def run_standalone_job_worker(stop_event: Optional[asyncio.Event] = None):
    await _jq_run_standalone_job_worker_impl(stop_event=stop_event, deps=_job_queue_bridge_deps())

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
    await _jq_job_worker_loop_impl(_job_queue_bridge_deps())


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

def _job_execution_runtime_deps() -> JobExecutionRuntimeDeps:
    return JobExecutionRuntimeDeps(
        state=state,
        logger=logger,
        apply_autopilot_policy_fn=_apply_autopilot_policy,
        job_get_fn=_job_get,
        job_update_fn=_job_update,
        job_now_fn=_job_now,
        queue_enqueue_fn=_queue_enqueue,
        validate_target_fn=validate_target,
        payload_for_user_id_fn=_payload_for_user_id,
        sqlmap_path=SQLMAP_PATH,
        sqlmap_non_interactive_flags_fn=_sqlmap_non_interactive_flags,
        header_scrubber_cls=HeaderScrubber,
        start_sqlmap_process_fn=_start_sqlmap_process,
        autopilot_max_phase=AUTOPILOT_MAX_PHASE,
        scan_timeout_total_seconds=SCAN_TIMEOUT_TOTAL_SECONDS,
        terminate_process_tree_fn=_terminate_process_tree,
        broadcast_fn=broadcast,
        scan_reader_task_fn=scan_reader_task,
        run_omni_surface_scan_fn=run_omni_surface_scan,
    )


async def _run_classic_job(scan_id: str, user_id: str, cfg: dict):
    await _job_exec_run_classic_job_impl(scan_id, user_id, cfg, _job_execution_runtime_deps())


async def _run_omni_job(scan_id: str, user_id: str, cfg: dict):
    await _job_exec_run_omni_job_impl(scan_id, user_id, cfg, _job_execution_runtime_deps())


async def _scan_timeout_watchdog(user_id: str, timeout_seconds: int):
    await _job_exec_scan_timeout_watchdog_impl(user_id, timeout_seconds, _job_execution_runtime_deps())

def _start_sqlmap_process(cmd: List[str]) -> subprocess.Popen:
    return _process_guard_start_sqlmap_process(
        cmd,
        rlimit_cpu_seconds=SCAN_RLIMIT_CPU_SECONDS,
        rlimit_as_mb=SCAN_RLIMIT_AS_MB,
    )

def _terminate_process_tree(proc: Optional[subprocess.Popen]):
    _process_guard_terminate_process_tree(proc)

def _host_allowed(host: str) -> bool:
    return _process_guard_host_allowed(host, ALLOWED_TARGETS)

_target_slug = _scan_utils_target_slug

def _safe_history_path(filename: str) -> str:
    return _scan_utils_safe_history_path(HISTORY_DIR, filename)

def _init_audit_db():
    _audit_store_init_audit_db(AUDIT_DB_PATH)


def _init_jobs_db():
    _pg_init_jobs_db_impl(_postgres_persistence_runtime_deps())


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

_job_persistence_facade = JobPersistenceFacade(
    deps_factory=_job_persistence_runtime_deps,
    job_now_fn=_job_now,
)
_job_create = _job_persistence_facade.create_job
_job_update = _job_persistence_facade.update_job
_job_get = _job_persistence_facade.get_job
_job_list = _job_persistence_facade.list_jobs
_fallback_coverage_response_from_job = _job_persistence_facade.fallback_coverage_response_from_job
_job_get_coverage_v1 = _job_persistence_facade.get_job_coverage_v1


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
        else []
    ),
    allow_origin_regex=(
        None
        if ENVIRONMENT == 'development'
        else r"^https://([A-Za-z0-9-]+\.)*cerberus\.local(?::\d+)?$"
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

# Health router
from backend.routers.health import router as health_router
app.include_router(health_router, prefix="/health", tags=["health"])

# Auth router (extracted from monolith)
from backend.routers.auth import router as auth_router
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# Admin router (extracted from monolith)
from backend.routers.admin import router as admin_router
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

sanitize_line = _log_output_sanitize_line
translate_log = _log_output_translate_log


from autopilot_utils import detect_defensive_measures

def _apply_autopilot_policy(cfg: dict, mode: str, phase: int = 1) -> dict:
    return _scan_utils_apply_autopilot_policy(cfg, mode, phase)

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

def _omni_surface_runtime_deps() -> OmniSurfaceRuntimeDeps:
    return OmniSurfaceRuntimeDeps(
        state_omni_meta=state.omni_meta,
        omni_allowed_vectors=OMNI_ALLOWED_VECTORS,
        scan_timeout_total_seconds=SCAN_TIMEOUT_TOTAL_SECONDS,
        sqlmap_path=SQLMAP_PATH,
        history_dir=HISTORY_DIR,
        history_store_plain=bool(HISTORY_STORE_PLAIN),
        canonical_job_kind=CANONICAL_JOB_KIND,
        preflight_fail_total=PREFLIGHT_FAIL_TOTAL,
        logger=logger,
        python_exec=(sys.executable or "python"),
        ensure_unified_cfg_aliases_fn=_ensure_unified_cfg_aliases,
        apply_autopilot_policy_fn=_apply_autopilot_policy,
        prepare_scan_context_fn=_omni_runtime_prepare_scan_context,
        compute_defended_heuristics_seed_fn=_omni_runtime_compute_defended_heuristics_seed,
        suspect_defended_target_fn=suspect_defended_target,
        merge_defended_heuristics_fn=_omni_runtime_merge_defended_heuristics,
        build_requested_engines_fn=_omni_runtime_build_requested_engines,
        run_registered_engines_unified_fn=_omni_engine_run_registered_engines_unified,
        build_engine_vectors_for_target_fn=_omni_runtime_build_engine_vectors_for_target,
        web_execute_mode_phases_fn=_omni_web_execute_mode_phases,
        nonweb_execute_mode_fn=_omni_nonweb_execute_mode,
        analyze_results_for_verdict_fn=_omni_runtime_analyze_results_for_verdict,
        finalize_coverage_fn=_omni_finalize_coverage,
        coverage_public_payload_fn=_coverage_public_payload,
        emit_verdict_metrics_fn=_emit_verdict_metrics,
        record_phase_durations_fn=_record_phase_durations_from_coverage,
        record_job_duration_fn=_record_job_duration,
        broadcast_fn=broadcast,
        broadcast_log_fn=broadcast_log,
        calibration_waf_detect_fn=calibration_waf_detect,
        build_vector_commands_fn=build_vector_commands,
        run_sqlmap_vector_fn=run_sqlmap_vector,
        direct_db_reachability_fn=direct_db_reachability,
        websocket_exploit_fn=websocket_exploit,
        mqtt_exploit_fn=mqtt_exploit,
        grpc_deep_fuzz_probe_fn=grpc_deep_fuzz_probe,
        make_history_paths_fn=_omni_history_make_history_paths,
        target_slug_fn=_target_slug,
        build_history_data_fn=_omni_history_build_history_data,
        set_evidence_count_fn=_omni_history_set_evidence_count,
        synthesize_structured_findings_fn=synthesize_structured_findings,
        persist_scan_artifacts_db_fn=_persist_scan_artifacts_db,
        persist_coverage_v1_db_fn=_persist_coverage_v1_db,
        persist_history_json_fn=_omni_history_persist_history_json,
        persist_encrypted_artifact_fn=_omni_history_persist_encrypted_artifact,
        job_update_fn=_job_update,
        job_now_fn=_job_now,
        coverage_ledger_cls=CoverageLedger,
        conclusive_blocker_cls=ConclusiveBlocker,
        phase_completion_record_cls=PhaseCompletionRecord,
        orchestrator_cls=Orchestrator,
        orchestrator_phase=OrchestratorPhase,
        polymorphic_evasion_cls=PolymorphicEvasionEngine,
        differential_validator_cls=DifferentialResponseValidator,
        browser_stealth_cls=BrowserStealth,
        engine_registry=engine_registry,
    )


async def run_omni_surface_scan(user_id: str, cfg: dict):
    return await _omni_surface_scan_impl(user_id, cfg, deps=_omni_surface_runtime_deps())

def _pending_jobs_count(user_id: str) -> int:
    return _job_count_db(user_id=str(user_id), statuses=["queued", "running"])

def _default_unified_vectors_from_cfg(cfg: dict) -> List[str]:
    return _scan_utils_default_unified_vectors_from_cfg(cfg, allowed_vectors=OMNI_ALLOWED_VECTORS)


def _normalize_unified_scan_cfg(raw_cfg: dict) -> dict:
    return _scan_utils_normalize_unified_scan_cfg(raw_cfg, allowed_vectors=OMNI_ALLOWED_VECTORS)


def _scan_start_metric_inc(kind: str) -> None:
    SCAN_START_TOTAL.labels(kind=str(kind or "unknown")).inc()


def _unified_queue_runtime_deps() -> UnifiedQueueRuntimeDeps:
    return UnifiedQueueRuntimeDeps(
        canonical_job_kind=CANONICAL_JOB_KIND,
        autopilot_max_phase=AUTOPILOT_MAX_PHASE,
        normalize_unified_scan_cfg_fn=_normalize_unified_scan_cfg,
        validate_omni_config_fn=validate_omni_config,
        read_unified_runtime_cfg_fn=_read_unified_runtime_cfg,
        validate_target_fn=validate_target,
        validate_network_host_fn=validate_network_host,
        pending_jobs_count_fn=_pending_jobs_count,
        job_create_fn=_job_create,
        queue_enqueue_fn=_queue_enqueue,
        ensure_job_background_tasks_fn=_ensure_job_background_tasks,
        scan_start_metric_inc_fn=_scan_start_metric_inc,
        audit_log_fn=audit_log,
        logger=logger,
    )


async def _queue_unified_scan(request: Request, current_user: JWTPayload, *, source_endpoint: str) -> dict:
    return await _queue_unified_scan_impl(
        request=request,
        current_user=current_user,
        source_endpoint=source_endpoint,
        deps=_unified_queue_runtime_deps(),
    )


@app.post("/scan/start")
@limiter.limit("20/minute")
async def start_scan(
    request: Request,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_CREATE))
):
    """Canonical unified scan start endpoint."""
    return await _queue_unified_scan(request, current_user, source_endpoint="/scan/start")


def _api_surface_ops_deps() -> ApiSurfaceOpsDeps:
    return ApiSurfaceOpsDeps(
        omni_allowed_modes=OMNI_ALLOWED_MODES,
        omni_allowed_vectors=OMNI_ALLOWED_VECTORS,
        running_kind_values=state.running_kind_by_user.values(),
        normalize_job_kind_fn=_normalize_job_kind,
        canonical_job_kind=CANONICAL_JOB_KIND,
        active_omni_scans_metric=ACTIVE_OMNI_SCANS,
        generate_latest_fn=generate_latest,
        content_type_latest=CONTENT_TYPE_LATEST,
        logger=logger,
        browser_stealth_cls=BrowserStealth,
    )


def _scan_capabilities_payload() -> Dict[str, Any]:
    return _api_surface_scan_capabilities_payload_impl(_api_surface_ops_deps())


@app.get("/scan/capabilities")
async def scan_capabilities(current_user: JWTPayload = Depends(require_permission(Permission.SCAN_READ))):
    return _scan_capabilities_payload()

@app.get("/metrics")
async def metrics(current_user: JWTPayload = Depends(require_permission(Permission.ADMIN_AUDIT))):
    return _api_surface_metrics_payload_impl(_api_surface_ops_deps())

@app.post("/setup/playwright")
@limiter.limit("5/minute")
async def setup_playwright(
    request: Request,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_CREATE))
):
    """Trigger manual browser installation for Playwright/Omni-Surface."""
    return await _api_surface_setup_playwright_payload_impl(
        username=str(current_user.username),
        deps=_api_surface_ops_deps(),
    )

def _cleanup_classic_scan_runtime(user_id: str) -> None:
    state.active_scans.pop(user_id, None)
    watchdog = state.scan_watchdogs.pop(user_id, None)
    if watchdog and not watchdog.done():
        watchdog.cancel()


def _classic_scan_runtime_deps() -> ClassicScanRuntimeDeps:
    return ClassicScanRuntimeDeps(
        state=state,
        logger=logger,
        smart_filter_cls=SmartFilterEngine,
        finding_parser_cls=FindingParser,
        broadcast_fn=broadcast,
        sanitize_line_fn=sanitize_line,
        translate_log_fn=translate_log,
        detect_defensive_measures_fn=detect_defensive_measures,
        autopilot_max_phase=AUTOPILOT_MAX_PHASE,
        apply_autopilot_policy_fn=_apply_autopilot_policy,
        sqlmap_path=SQLMAP_PATH,
        sqlmap_non_interactive_flags_fn=_sqlmap_non_interactive_flags,
        header_scrubber_cls=HeaderScrubber,
        start_sqlmap_process_fn=_start_sqlmap_process,
        terminate_process_tree_fn=_terminate_process_tree,
        job_update_fn=_job_update,
        job_now_fn=_job_now,
        canonical_job_kind=CANONICAL_JOB_KIND,
        coverage_public_payload_fn=_coverage_public_payload,
        emit_verdict_metrics_fn=_emit_verdict_metrics,
        record_phase_durations_from_coverage_fn=_record_phase_durations_from_coverage,
        record_job_duration_fn=_record_job_duration,
        build_multi_profile_reports_fn=build_multi_profile_reports,
        persist_scan_artifacts_db_fn=_persist_scan_artifacts_db,
        persist_coverage_v1_db_fn=_persist_coverage_v1_db,
        target_slug_fn=_target_slug,
        history_dir=HISTORY_DIR,
        history_store_plain=HISTORY_STORE_PLAIN,
        audit_log_fn=audit_log,
        cleanup_scan_runtime_fn=_cleanup_classic_scan_runtime,
    )


async def scan_reader_task(user_id: str):
    await _classic_scan_reader_task_impl(user_id, _classic_scan_runtime_deps())


async def start_next_phase(user_id: str, scan_info: dict):
    await _classic_start_next_phase_impl(user_id, scan_info, _classic_scan_runtime_deps())


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
from backend.routers.history import router as history_router
app.include_router(history_router, prefix="/history", tags=["history"])
app.include_router(loot_router, prefix="/api/loot", tags=["loot"])
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
from backend.routers.c2 import router as c2_router
app.include_router(c2_router, prefix="/c2", tags=["c2"])
# Agent management also accessible via /auth and /admin prefixes
app.include_router(c2_router, prefix="/auth/agent", tags=["agents"], include_in_schema=False)
app.include_router(c2_router, prefix="/admin/agents", tags=["agents"], include_in_schema=False)
# [AGENT + C2 ENDPOINTS EXTRACTED TO routers/c2.py]

# Offensive router (extracted from monolith)
from backend.routers.offensive import router as offensive_router
from backend.routers.ai import router as ai_router
app.include_router(offensive_router, tags=["offensive"])
app.include_router(ai_router, prefix="/ai", tags=["ai"])
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


# Reconnect internal engine telemetry to frontend websocket clients.
CerberusBroadcaster.register_ws_handler(broadcast)


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

@app.post("/admin/jobs/kick")
async def admin_kick_jobs(
    force_start: bool = False,
    current_user: JWTPayload = Depends(require_permission(Permission.SCAN_MODIFY)),
):
    return await _system_ops_admin_kick_jobs_payload_impl(
        deps=_system_ops_runtime_deps(),
        force_start=bool(force_start),
    )


@app.post("/admin/killswitch")
async def admin_killswitch(
    current_user: JWTPayload = Depends(require_permission(Permission.ADMIN_KILLSWITCH)),
):
    """Emergency Stop: Halts all system activities and prevents new jobs."""
    state.kill_switch_active = True
    logger.critical(f"🚨 KILL-SWITCH TRIGGERED by {current_user.sub}")
    
    # Cancel all running job tasks
    active_tasks = list(state.current_job_task_by_user.values())
    for t in active_tasks:
        if not t.done():
            t.cancel()
    
    # Broadcast through WebSockets
    try:
        await _ws_broadcast_impl(
            {"type": "system_event", "event": "kill_switch_triggered", "operator": current_user.sub},
            deps=_ws_runtime_deps()
        )
    except Exception:
        pass
        
    return {"status": "triggered", "cancelled_tasks": len(active_tasks)}


@app.get("/status")
async def get_status(current_user: JWTPayload = Depends(get_current_user)):
    return _system_ops_status_payload_impl(deps=_system_ops_runtime_deps())

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom error response"""
    return _api_surface_http_exception_payload_impl(exc)

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








