"""PostgreSQL persistence backend for jobs, scans, ledgers and verdicts."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg_pool import AsyncConnectionPool
except Exception:  # pragma: no cover - optional dependency at runtime
    psycopg = None
    dict_row = None
    AsyncConnectionPool = None


logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_kind(kind: Any) -> str:
    value = str(kind or "").strip().lower()
    if value in {"unified", "classic", "omni"}:
        return "unified"
    return value or "unified"


def normalize_database_url(database_url: str) -> str:
    url = (database_url or "").strip()
    if url.startswith("postgresql+psycopg://"):
        return "postgresql://" + url.split("://", 1)[1]
    return url


@dataclass
class PostgresStore:
    database_url: str
    pool: Optional[Any] = field(default=None, init=False)

    @classmethod
    def from_env(cls, database_url: str) -> Optional["PostgresStore"]:
        dsn = normalize_database_url(database_url)
        if not dsn:
            return None
        if psycopg is None or AsyncConnectionPool is None:
            logger.warning("DATABASE_URL set but psycopg/psycopg-pool is not installed. PostgreSQL backend disabled.")
            return None
        if not dsn.startswith("postgresql://"):
            logger.warning("DATABASE_URL does not look like a PostgreSQL DSN. Backend disabled.")
            return None
        return cls(database_url=dsn)

    async def open(self) -> None:
        """Initialize the connection pool."""
        if self.pool:
            return
        logger.info("🔌 Connecting to PostgreSQL (async pool)...")
        try:
            self.pool = AsyncConnectionPool(
                self.database_url,
                min_size=1,
                max_size=10,
                open=False,
                kwargs={"row_factory": dict_row}
            )
            await self.pool.open()
            await self.pool.wait() # Wait for the pool to be ready
            logger.info("✅ PostgreSQL pool ready")
        except Exception as e:
            logger.error(f"❌ Failed to init PostgreSQL pool: {e}")
            self.pool = None

    async def close(self) -> None:
        """Close the connection pool."""
        if self.pool:
            await self.pool.close()
            self.pool = None
            logger.info("🔌 PostgreSQL pool closed")

    async def ensure_schema(self) -> None:
        if not self.pool:
            # If ensure_schema is called (e.g. from migrate.py), we might need to open/close locally if pool not ready.
            # But usually we expect open() to be called.
            # For migrate.py which is a script, it should call open().
            pass

        migrations_dir = Path(__file__).resolve().parent / "migrations"
        migrations = sorted(migrations_dir.glob("*.sql"))
        if not migrations:
            return

        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version TEXT PRIMARY KEY,
                        applied_at TEXT NOT NULL
                    )
                    """
                )
                await cur.execute("SELECT version FROM schema_migrations")
                applied = {str(r["version"]) for r in await cur.fetchall()}

                for migration in migrations:
                    version = migration.name
                    if version in applied:
                        continue
                    sql = migration.read_text(encoding="utf-8")
                    await cur.execute(sql)
                    await cur.execute(
                        "INSERT INTO schema_migrations(version, applied_at) VALUES (%s, %s)",
                        (version, _utc_now_iso()),
                    )
                # Connection context manager auto-commits if no exception

    @staticmethod
    def _loads_json(value: Any, default: Any) -> Any:
        if value is None:
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(str(value))
        except Exception:
            return default

    @staticmethod
    def _dumps_json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)

    async def recover_running_jobs(self, stale_seconds: int) -> None:
        if not self.pool: return
        now = datetime.now(timezone.utc)
        now_iso = _utc_now_iso()
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT scan_id, heartbeat_at FROM jobs WHERE status = %s", ("running",))
                rows = await cur.fetchall()
                for row in rows:
                    heartbeat_at = row.get("heartbeat_at")
                    stale = True
                    try:
                        if heartbeat_at:
                            hb = datetime.fromisoformat(str(heartbeat_at))
                            stale = (now - hb).total_seconds() >= int(stale_seconds)
                    except Exception:
                        stale = True
                    reason = "backend_restarted_stale" if stale else "backend_restarted"
                    await cur.execute(
                        "UPDATE jobs SET status=%s, finished_at=%s, error=%s WHERE scan_id=%s",
                        ("interrupted", now_iso, reason, str(row.get("scan_id"))),
                    )

    async def list_job_ids_by_status(self, status: str) -> List[str]:
        if not self.pool: return []
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT scan_id FROM jobs WHERE status = %s ORDER BY created_at ASC",
                    (str(status),),
                )
                rows = await cur.fetchall()
        return [str(r.get("scan_id")) for r in rows]

    async def create_job(
        self,
        *,
        scan_id: str,
        user_id: str,
        kind: str,
        status: str,
        phase: int,
        max_phase: int,
        autopilot: bool,
        target_url: str,
        cfg: Dict[str, Any],
        pid: Optional[int] = None,
        priority: int = 0,
    ) -> None:
        if not self.pool: return
        now_iso = _utc_now_iso()
        kind_norm = _normalize_kind(kind)
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO jobs
                    (scan_id, user_id, kind, status, created_at, started_at, phase, max_phase, autopilot, target_url, config_json, pid, worker_id, heartbeat_at, attempts, priority)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        kind = EXCLUDED.kind,
                        status = EXCLUDED.status,
                        created_at = EXCLUDED.created_at,
                        started_at = EXCLUDED.started_at,
                        phase = EXCLUDED.phase,
                        max_phase = EXCLUDED.max_phase,
                        autopilot = EXCLUDED.autopilot,
                        target_url = EXCLUDED.target_url,
                        config_json = EXCLUDED.config_json,
                        pid = EXCLUDED.pid,
                        priority = EXCLUDED.priority
                    """,
                    (
                        str(scan_id),
                        str(user_id),
                        kind_norm,
                        str(status),
                        now_iso,
                        now_iso if status == "running" else None,
                        int(phase),
                        int(max_phase),
                        1 if autopilot else 0,
                        str(target_url),
                        self._dumps_json(cfg or {}),
                        int(pid) if pid is not None else None,
                        None,
                        None,
                        0,
                        int(priority),
                    ),
                )

    async def update_job(self, scan_id: str, updates: Dict[str, Any]) -> None:
        if not self.pool: return
        if not updates:
            return
        allowed = {
            "status",
            "started_at",
            "finished_at",
            "phase",
            "max_phase",
            "pid",
            "worker_id",
            "heartbeat_at",
            "attempts",
            "priority",
            "result_filename",
            "vulnerable",
            "error",
            "config_json",
        }
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return

        cols = ", ".join([f"{k} = %s" for k in fields.keys()])
        values = list(fields.values())
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(f"UPDATE jobs SET {cols} WHERE scan_id = %s", (*values, str(scan_id)))

    async def get_job(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not self.pool: return None
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT scan_id,user_id,kind,status,created_at,started_at,finished_at,phase,max_phase,autopilot,target_url,config_json,pid,worker_id,heartbeat_at,attempts,priority,result_filename,vulnerable,error
                    FROM jobs WHERE scan_id = %s
                    """,
                    (str(scan_id),),
                )
                row = await cur.fetchone()
        if not row:
            return None
        out = dict(row)
        out["kind"] = _normalize_kind(out.get("kind"))
        out["config"] = self._loads_json(out.pop("config_json", "{}"), {})
        out["autopilot"] = bool(out.get("autopilot"))
        if out.get("vulnerable") is not None:
            out["vulnerable"] = bool(out["vulnerable"])
        return out

    async def list_jobs(self, user_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self.pool: return []
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT scan_id,kind,status,created_at,started_at,finished_at,phase,max_phase,autopilot,target_url,pid,worker_id,heartbeat_at,attempts,priority,result_filename,vulnerable,error
                    FROM jobs WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (str(user_id), int(limit)),
                )
                rows = await cur.fetchall()
        out: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["kind"] = _normalize_kind(item.get("kind"))
            item["autopilot"] = bool(item.get("autopilot"))
            if item.get("vulnerable") is not None:
                item["vulnerable"] = bool(item["vulnerable"])
            out.append(item)
        return out

    async def count_jobs(self, *, user_id: Optional[str] = None, statuses: Optional[Sequence[str]] = None) -> int:
        if not self.pool: return 0
        clauses = []
        params: List[Any] = []
        if user_id is not None:
            clauses.append("user_id = %s")
            params.append(str(user_id))
        if statuses:
            placeholders = ",".join(["%s"] * len(statuses))
            clauses.append(f"status IN ({placeholders})")
            params.extend([str(s) for s in statuses])
        where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(1) AS c FROM jobs{where_sql}"
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(sql, tuple(params))
                row = await cur.fetchone()
        return int((row or {}).get("c", 0))

    async def latest_active_job_scan_id(self, *, user_id: str, kinds: Sequence[str]) -> Optional[str]:
        if not self.pool: return None
        kind_values = [str(k).strip().lower() for k in (kinds or []) if str(k).strip()]
        if not kind_values:
            return None
        placeholders = ",".join(["%s"] * len(kind_values))
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    f"""
                    SELECT scan_id
                    FROM jobs
                    WHERE user_id = %s AND kind IN ({placeholders}) AND status IN ('queued','running')
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (str(user_id), *kind_values),
                )
                row = await cur.fetchone()
        if not row:
            return None
        return str(row.get("scan_id"))

    async def persist_scan_artifacts(
        self,
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
        cfg: Optional[Dict[str, Any]],
        coverage: Optional[Dict[str, Any]],
        report_data: Optional[Dict[str, Any]],
        finished_at: Optional[str] = None,
    ) -> None:
        if not self.pool: return
        if not scan_id:
            return

        now_iso = _utc_now_iso()
        kind_norm = _normalize_kind(kind)
        coverage_json = self._dumps_json(coverage or {})
        report_json = self._dumps_json(report_data or {})
        reasons = (coverage or {}).get("conclusive_blockers") or []
        reasons_json = self._dumps_json(reasons)

        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO scans
                    (scan_id,user_id,kind,target_url,mode,profile,status,verdict,conclusive,vulnerable,count,evidence_count,results_count,message,created_at,updated_at,finished_at,config_json,report_json)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        user_id=EXCLUDED.user_id,
                        kind=EXCLUDED.kind,
                        target_url=EXCLUDED.target_url,
                        mode=EXCLUDED.mode,
                        profile=EXCLUDED.profile,
                        status=EXCLUDED.status,
                        verdict=EXCLUDED.verdict,
                        conclusive=EXCLUDED.conclusive,
                        vulnerable=EXCLUDED.vulnerable,
                        count=EXCLUDED.count,
                        evidence_count=EXCLUDED.evidence_count,
                        results_count=EXCLUDED.results_count,
                        message=EXCLUDED.message,
                        updated_at=EXCLUDED.updated_at,
                        finished_at=EXCLUDED.finished_at,
                        config_json=EXCLUDED.config_json,
                        report_json=EXCLUDED.report_json
                    """,
                    (
                        str(scan_id),
                        str(user_id),
                        kind_norm,
                        str(target_url or ""),
                        (str(mode) if mode else None),
                        (str(profile) if profile else None),
                        str(status),
                        (str(verdict) if verdict else None),
                        (1 if conclusive is True else (0 if conclusive is False else None)),
                        (1 if vulnerable is True else (0 if vulnerable is False else None)),
                        (int(count) if count is not None else None),
                        (int(evidence_count) if evidence_count is not None else None),
                        (int(results_count) if results_count is not None else None),
                        (str(message) if message else None),
                        now_iso,
                        now_iso,
                        finished_at or now_iso,
                        self._dumps_json(cfg or {}),
                        report_json,
                    ),
                )
                if coverage:
                    await cur.execute(
                        "INSERT INTO ledgers (scan_id, coverage_json, created_at) VALUES (%s, %s, %s)",
                        (str(scan_id), coverage_json, now_iso),
                    )
                if verdict:
                    await cur.execute(
                        """
                        INSERT INTO verdicts
                        (scan_id, verdict, conclusive, vulnerable, reasons_json, coverage_json, created_at, updated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (scan_id) DO UPDATE SET
                            verdict=EXCLUDED.verdict,
                            conclusive=EXCLUDED.conclusive,
                            vulnerable=EXCLUDED.vulnerable,
                            reasons_json=EXCLUDED.reasons_json,
                            coverage_json=EXCLUDED.coverage_json,
                            updated_at=EXCLUDED.updated_at
                        """,
                        (
                            str(scan_id),
                            str(verdict),
                            (1 if conclusive is True else (0 if conclusive is False else 0)),
                            (1 if vulnerable is True else (0 if vulnerable is False else None)),
                            reasons_json,
                            coverage_json,
                            now_iso,
                            now_iso,
                        ),
                    )

    async def persist_coverage_v1(
        self,
        *,
        scan_id: str,
        version: str,
        job_status: str,
        verdict: str,
        conclusive: bool,
        vulnerable: bool,
        coverage_summary: Dict[str, Any],
        conclusive_blockers: List[Dict[str, Any]],
        phase_records: List[Dict[str, Any]],
        vector_records: List[Dict[str, Any]],
    ) -> None:
        if not self.pool: return
        if not scan_id:
            return
        now_iso = _utc_now_iso()
        summary_json = self._dumps_json(coverage_summary or {})

        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO coverage_reports
                    (scan_id, schema_version, job_status, verdict, conclusive, vulnerable, coverage_summary, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        schema_version=EXCLUDED.schema_version,
                        job_status=EXCLUDED.job_status,
                        verdict=EXCLUDED.verdict,
                        conclusive=EXCLUDED.conclusive,
                        vulnerable=EXCLUDED.vulnerable,
                        coverage_summary=EXCLUDED.coverage_summary,
                        updated_at=EXCLUDED.updated_at
                    """,
                    (
                        str(scan_id),
                        str(version or "coverage.v1"),
                        str(job_status or "unknown"),
                        str(verdict or "INCONCLUSIVE"),
                        bool(conclusive),
                        bool(vulnerable),
                        summary_json,
                        now_iso,
                        now_iso,
                    ),
                )

                await cur.execute("DELETE FROM coverage_blockers WHERE scan_id = %s", (str(scan_id),))
                for blocker in conclusive_blockers or []:
                    if not isinstance(blocker, dict):
                        continue
                    await cur.execute(
                        """
                        INSERT INTO coverage_blockers
                        (scan_id, code, message, detail, phase, recoverable, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            str(scan_id),
                            str(blocker.get("code") or "unknown"),
                            str(blocker.get("message") or ""),
                            self._dumps_json(blocker.get("detail")) if blocker.get("detail") is not None else None,
                            (str(blocker.get("phase")) if blocker.get("phase") else None),
                            (bool(blocker.get("recoverable")) if blocker.get("recoverable") is not None else None),
                            now_iso,
                        ),
                    )

                await cur.execute("DELETE FROM coverage_phase_records WHERE scan_id = %s", (str(scan_id),))
                for phase in phase_records or []:
                    if not isinstance(phase, dict):
                        continue
                    raw_status = str(phase.get("status") or "partial").lower()
                    status = raw_status if raw_status in {"completed", "partial", "failed", "timeout"} else "partial"
                    notes = phase.get("notes") if isinstance(phase.get("notes"), list) else []
                    await cur.execute(
                        """
                        INSERT INTO coverage_phase_records
                        (scan_id, phase, status, duration_ms, items_processed, items_failed, notes, started_at, ended_at, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            str(scan_id),
                            str(phase.get("phase") or "unknown"),
                            status,
                            max(0, int(phase.get("duration_ms") or 0)),
                            max(0, int(phase.get("items_processed") or 0)),
                            max(0, int(phase.get("items_failed") or 0)),
                            self._dumps_json(notes),
                            phase.get("started_at"),
                            phase.get("ended_at"),
                            now_iso,
                        ),
                    )

                await cur.execute("DELETE FROM coverage_vector_records WHERE scan_id = %s", (str(scan_id),))
                for vector in vector_records or []:
                    if not isinstance(vector, dict):
                        continue
                    raw_status = str(vector.get("status") or "PENDING").upper()
                    status = raw_status if raw_status in {"EXECUTED", "QUEUED", "FAILED", "SKIPPED", "PENDING", "TIMEOUT"} else "PENDING"
                    detail = {
                        k: v
                        for k, v in vector.items()
                        if k
                        not in {
                            "id",
                            "vector_id",
                            "vector_name",
                            "engine",
                            "status",
                            "inputs_found",
                            "inputs_tested",
                            "inputs_failed",
                            "duration_ms",
                            "error",
                            "evidence",
                            "detail",
                        }
                    }
                    merged_detail = {}
                    if isinstance(vector.get("detail"), dict):
                        merged_detail.update(vector.get("detail") or {})
                    merged_detail.update(detail)
                    evidence = vector.get("evidence") if isinstance(vector.get("evidence"), list) else []
                    await cur.execute(
                        """
                        INSERT INTO coverage_vector_records
                        (scan_id, vector_id, vector_name, engine, status, inputs_found, inputs_tested, inputs_failed, duration_ms, error, evidence, detail, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            str(scan_id),
                            str(vector.get("vector_id") or "unknown"),
                            str(vector.get("vector_name") or str(vector.get("vector_id") or "unknown")),
                            str(vector.get("engine") or "unknown"),
                            status,
                            max(0, int(vector.get("inputs_found") or 0)),
                            max(0, int(vector.get("inputs_tested") or 0)),
                            max(0, int(vector.get("inputs_failed") or 0)),
                            max(0, int(vector.get("duration_ms") or 0)),
                            (str(vector.get("error")) if vector.get("error") else None),
                            self._dumps_json(evidence),
                            self._dumps_json(merged_detail),
                            now_iso,
                        ),
                    )

    async def get_coverage_v1(
        self,
        *,
        scan_id: str,
        limit: int = 50,
        cursor: int = 0,
    ) -> Optional[Dict[str, Any]]:
        if not self.pool: return None
        if not scan_id:
            return None
        lim = max(1, min(int(limit), 500))
        cur_id = max(0, int(cursor))
        async with self.pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT scan_id, schema_version, job_status, verdict, conclusive, vulnerable, coverage_summary, updated_at
                    FROM coverage_reports
                    WHERE scan_id = %s
                    """,
                    (str(scan_id),),
                )
                report_row = await cur.fetchone()
                if not report_row:
                    return None

                await cur.execute(
                    """
                    SELECT code, message, detail, phase, recoverable
                    FROM coverage_blockers
                    WHERE scan_id = %s
                    ORDER BY id ASC
                    """,
                    (str(scan_id),),
                )
                blocker_rows = await cur.fetchall()

                await cur.execute(
                    """
                    SELECT phase, status, duration_ms, items_processed, items_failed, notes, started_at, ended_at
                    FROM coverage_phase_records
                    WHERE scan_id = %s
                    ORDER BY id ASC
                    """,
                    (str(scan_id),),
                )
                phase_rows = await cur.fetchall()

                await cur.execute(
                    """
                    SELECT id, vector_id, vector_name, engine, status, inputs_tested, duration_ms, error
                    FROM coverage_vector_records
                    WHERE scan_id = %s AND id > %s
                    ORDER BY id ASC
                    LIMIT %s
                    """,
                    (str(scan_id), cur_id, lim + 1),
                )
                vector_rows = await cur.fetchall()

        summary = self._loads_json(report_row.get("coverage_summary"), {})
        blockers: List[Dict[str, Any]] = []
        for row in blocker_rows:
            blockers.append(
                {
                    "code": str(row.get("code") or "unknown"),
                    "message": str(row.get("message") or ""),
                    "detail": self._loads_json(row.get("detail"), row.get("detail")),
                    "phase": (str(row.get("phase")) if row.get("phase") else None),
                    "recoverable": (bool(row.get("recoverable")) if row.get("recoverable") is not None else None),
                }
            )

        phases: List[Dict[str, Any]] = []
        for row in phase_rows:
            started_at = row.get("started_at")
            ended_at = row.get("ended_at")
            phases.append(
                {
                    "phase": str(row.get("phase") or "unknown"),
                    "status": str(row.get("status") or "partial"),
                    "duration_ms": max(0, int(row.get("duration_ms") or 0)),
                    "items_processed": max(0, int(row.get("items_processed") or 0)),
                    "items_failed": max(0, int(row.get("items_failed") or 0)),
                    "notes": self._loads_json(row.get("notes"), []),
                    "started_at": (started_at.isoformat() if hasattr(started_at, "isoformat") else (str(started_at) if started_at else None)),
                    "ended_at": (ended_at.isoformat() if hasattr(ended_at, "isoformat") else (str(ended_at) if ended_at else None)),
                }
            )

        has_more = len(vector_rows) > lim
        page_rows = vector_rows[:lim]
        next_cursor = int(page_rows[-1]["id"]) if (has_more and page_rows) else None
        vectors: List[Dict[str, Any]] = []
        for row in page_rows:
            vectors.append(
                {
                    "id": int(row.get("id")),
                    "vector_id": str(row.get("vector_id") or "unknown"),
                    "vector_name": str(row.get("vector_name") or str(row.get("vector_id") or "unknown")),
                    "engine": str(row.get("engine") or "unknown"),
                    "status": str(row.get("status") or "PENDING"),
                    "inputs_tested": max(0, int(row.get("inputs_tested") or 0)),
                    "duration_ms": max(0, int(row.get("duration_ms") or 0)),
                    "error": (str(row.get("error")) if row.get("error") else None),
                }
            )

        generated_at = report_row.get("updated_at")
        if hasattr(generated_at, "isoformat"):
            generated_at = generated_at.isoformat()
        elif generated_at is not None:
            generated_at = str(generated_at)
        else:
            generated_at = _utc_now_iso()

        return {
            "version": str(report_row.get("schema_version") or "coverage.v1"),
            "scan_id": str(report_row.get("scan_id") or scan_id),
            "job_status": str(report_row.get("job_status") or "unknown"),
            "verdict": str(report_row.get("verdict") or "INCONCLUSIVE"),
            "conclusive": bool(report_row.get("conclusive")),
            "vulnerable": bool(report_row.get("vulnerable")),
            "coverage_summary": summary,
            "conclusive_blockers": blockers,
            "phase_records": phases,
            "vector_records_page": {
                "limit": lim,
                "cursor": cur_id,
                "next_cursor": next_cursor,
                "has_more": has_more,
                "items": vectors,
            },
            "generated_at": str(generated_at),
        }
