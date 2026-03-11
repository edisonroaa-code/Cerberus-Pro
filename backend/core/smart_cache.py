from __future__ import annotations

import asyncio
import hashlib
import json
import math
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence, TypeVar


T = TypeVar("T")
_GLOBAL_CACHE: Optional["SmartCache"] = None
_GLOBAL_CACHE_LOCK = threading.Lock()


class PathDecision(str, Enum):
    FAST_PATH = "fast_path"
    SLOW_PATH = "slow_path"


@dataclass(frozen=True)
class StrategyScore:
    strategy: Any
    raw_success_rate: float
    effective_success_rate: float
    attempts: int
    age_seconds: float


class SmartCache:
    """
    SQLite-backed adaptive cache with feedback learning.

    Key capabilities:
    - Persistent strategy memory across process restarts.
    - Time decay on old records to avoid stale fast-path decisions.
    - Thread-safe SQLite access with retry on lock contention.
    - Autonomous purge of irrecoverable low-performing strategies.
    """

    def __init__(
        self,
        db_path: str = "smart_cache.sqlite3",
        *,
        min_success_rate: float = 0.50,
        decay_grace_days: float = 7.0,
        decay_half_life_days: float = 7.0,
        busy_timeout_ms: int = 5000,
        max_lock_retries: int = 4,
        lock_retry_base_sec: float = 0.05,
        strategy_encoder: Optional[Callable[[Any], str]] = None,
        strategy_decoder: Optional[Callable[[str], Any]] = None,
    ) -> None:
        if not (0.0 <= min_success_rate <= 1.0):
            raise ValueError("min_success_rate must be in [0, 1]")
        if decay_grace_days < 0:
            raise ValueError("decay_grace_days must be >= 0")
        if decay_half_life_days <= 0:
            raise ValueError("decay_half_life_days must be > 0")
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be >= 0")
        if max_lock_retries < 0:
            raise ValueError("max_lock_retries must be >= 0")
        if lock_retry_base_sec < 0:
            raise ValueError("lock_retry_base_sec must be >= 0")

        self.min_success_rate = min_success_rate
        self.decay_grace_days = decay_grace_days
        self.decay_half_life_days = decay_half_life_days
        self.max_lock_retries = max_lock_retries
        self.lock_retry_base_sec = lock_retry_base_sec

        self._strategy_encoder = strategy_encoder or self._default_encode
        self._strategy_decoder = strategy_decoder or self._default_decode
        self._lock = threading.RLock()

        db_parent = Path(db_path).expanduser().resolve().parent
        db_parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(Path(db_path).expanduser().resolve()),
            timeout=max(1.0, busy_timeout_ms / 1000.0),
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._configure_connection(busy_timeout_ms)
        self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SmartCache":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def generate_fingerprint(self, context_data: Mapping[str, Any]) -> str:
        payload = json.dumps(
            context_data,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def get_cached_strategy(self, context_data: Mapping[str, Any]) -> Optional[Any]:
        """
        Returns the best decayed strategy for the given context (Async).
        """
        return await asyncio.to_thread(self._get_cached_strategy_sync, context_data)

    def _get_cached_strategy_sync(self, context_data: Mapping[str, Any]) -> Optional[Any]:
        """
        Internal synchronous implementation of get_cached_strategy.
        """
        fingerprint = self.generate_fingerprint(context_data)
        rows = self._query_all(
            """
            SELECT strategy_blob, successes, failures, last_updated
            FROM cache_entries
            WHERE fingerprint = ?
            """,
            (fingerprint,),
        )

        best: Optional[StrategyScore] = None
        now = time.time()

        for row in rows:
            successes = int(row["successes"])
            failures = int(row["failures"])
            attempts = successes + failures
            if attempts <= 0:
                continue

            raw_rate = float(successes) / float(attempts)
            age_seconds = max(0.0, now - float(row["last_updated"]))
            effective_rate = self._apply_time_decay(raw_rate, age_seconds)
            strategy = self._strategy_decoder(str(row["strategy_blob"]))

            score = StrategyScore(
                strategy=strategy,
                raw_success_rate=raw_rate,
                effective_success_rate=effective_rate,
                attempts=attempts,
                age_seconds=age_seconds,
            )
            if best is None or score.effective_success_rate > best.effective_success_rate:
                best = score

        if best and best.effective_success_rate >= self.min_success_rate:
            return best.strategy
        return None

    def resolve_strategy(
        self,
        context_data: Mapping[str, Any],
        slow_path: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> tuple[T, PathDecision]:
        """
        Decision helper:
        - If a valid cached strategy exists, returns it with FAST_PATH.
        - Otherwise computes via slow_path and returns SLOW_PATH.
        """
        cached = self.get_cached_strategy(context_data)
        if cached is not None:
            return cached, PathDecision.FAST_PATH
        return slow_path(context_data, *args, **kwargs), PathDecision.SLOW_PATH

    async def update_feedback(
        self,
        context_data: Mapping[str, Any],
        strategy: Any,
        success: bool,
    ) -> None:
        """Updates feedback for a strategy (Async)."""
        await asyncio.to_thread(self._update_feedback_sync, context_data, strategy, success)

    def _update_feedback_sync(
        self,
        context_data: Mapping[str, Any],
        strategy: Any,
        success: bool,
    ) -> None:
        fingerprint = self.generate_fingerprint(context_data)
        strategy_blob = self._strategy_encoder(strategy)
        strategy_key = hashlib.sha256(strategy_blob.encode("utf-8")).hexdigest()

        success_inc = 1 if success else 0
        failure_inc = 0 if success else 1
        now = time.time()

        self._execute_write(
            """
            INSERT INTO cache_entries (
                fingerprint, strategy_key, strategy_blob,
                successes, failures, created_at, last_updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint, strategy_key)
            DO UPDATE SET
                strategy_blob = excluded.strategy_blob,
                successes = cache_entries.successes + excluded.successes,
                failures = cache_entries.failures + excluded.failures,
                last_updated = excluded.last_updated
            """,
            (
                fingerprint,
                strategy_key,
                strategy_blob,
                success_inc,
                failure_inc,
                now,
                now,
            ),
        )

    async def purge_obsolete_records(
        self,
        *,
        min_attempts: int = 10,
        irrecoverable_success_rate: float = 0.20,
    ) -> int:
        """Deletes physically low-performing records (Async)."""
        return await asyncio.to_thread(
            self._purge_obsolete_records_sync,
            min_attempts=min_attempts,
            irrecoverable_success_rate=irrecoverable_success_rate
        )

    def _purge_obsolete_records_sync(
        self,
        *,
        min_attempts: int = 10,
        irrecoverable_success_rate: float = 0.20,
    ) -> int:
        """
        Deletes physically low-performing records:
        success_rate < irrecoverable_success_rate after min_attempts or more.
        """
        if min_attempts <= 0:
            raise ValueError("min_attempts must be > 0")
        if not (0.0 <= irrecoverable_success_rate <= 1.0):
            raise ValueError("irrecoverable_success_rate must be in [0, 1]")

        rowcount = self._execute_write(
            """
            DELETE FROM cache_entries
            WHERE (successes + failures) >= ?
              AND (CAST(successes AS REAL) / CAST((successes + failures) AS REAL)) < ?
            """,
            (min_attempts, irrecoverable_success_rate),
        )
        return rowcount

    def stats_for_context(self, context_data: Mapping[str, Any]) -> list[StrategyScore]:
        """
        Optional diagnostics helper: returns ranked scores for all strategies in a context.
        """
        fingerprint = self.generate_fingerprint(context_data)
        rows = self._query_all(
            """
            SELECT strategy_blob, successes, failures, last_updated
            FROM cache_entries
            WHERE fingerprint = ?
            """,
            (fingerprint,),
        )

        now = time.time()
        scores: list[StrategyScore] = []
        for row in rows:
            successes = int(row["successes"])
            failures = int(row["failures"])
            attempts = successes + failures
            if attempts <= 0:
                continue

            raw_rate = float(successes) / float(attempts)
            age_seconds = max(0.0, now - float(row["last_updated"]))
            effective_rate = self._apply_time_decay(raw_rate, age_seconds)
            scores.append(
                StrategyScore(
                    strategy=self._strategy_decoder(str(row["strategy_blob"])),
                    raw_success_rate=raw_rate,
                    effective_success_rate=effective_rate,
                    attempts=attempts,
                    age_seconds=age_seconds,
                )
            )
        scores.sort(key=lambda item: item.effective_success_rate, reverse=True)
        return scores

    def _configure_connection(self, busy_timeout_ms: int) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)};")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.commit()

    def _create_schema(self) -> None:
        self._execute_write(
            """
            CREATE TABLE IF NOT EXISTS cache_entries (
                fingerprint TEXT NOT NULL,
                strategy_key TEXT NOT NULL,
                strategy_blob TEXT NOT NULL,
                successes INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                last_updated REAL NOT NULL,
                PRIMARY KEY (fingerprint, strategy_key)
            )
            """
        )
        self._execute_write(
            """
            CREATE INDEX IF NOT EXISTS idx_cache_entries_fp_updated
            ON cache_entries (fingerprint, last_updated DESC)
            """
        )

    def _apply_time_decay(self, raw_success_rate: float, age_seconds: float) -> float:
        if raw_success_rate <= 0.0:
            return 0.0
        if raw_success_rate >= 1.0 and age_seconds <= self.decay_grace_days * 86400.0:
            return 1.0

        age_days = age_seconds / 86400.0
        if age_days <= self.decay_grace_days:
            return raw_success_rate

        overdue_days = age_days - self.decay_grace_days
        decay_factor = math.exp(-math.log(2.0) * overdue_days / self.decay_half_life_days)
        return raw_success_rate * decay_factor

    def _query_all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        def op() -> list[sqlite3.Row]:
            with self._lock:
                cur = self._conn.execute(sql, params)
                return cur.fetchall()

        return self._with_retry(op)

    def _execute_write(self, sql: str, params: Sequence[Any] = ()) -> int:
        def op() -> int:
            with self._lock:
                cur = self._conn.cursor()
                try:
                    cur.execute("BEGIN IMMEDIATE")
                    cur.execute(sql, params)
                    affected = cur.rowcount
                    self._conn.commit()
                    return int(affected if affected is not None else 0)
                except Exception:
                    self._conn.rollback()
                    raise
                finally:
                    cur.close()

        return self._with_retry(op)

    def _with_retry(self, fn: Callable[[], T]) -> T:
        retries = self.max_lock_retries
        for attempt in range(retries + 1):
            try:
                return fn()
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                is_lock_error = "database is locked" in message or "database table is locked" in message
                if not is_lock_error or attempt >= retries:
                    raise
                sleep_time = self.lock_retry_base_sec * (2 ** attempt)
                time.sleep(sleep_time)
        raise RuntimeError("unreachable")

    @staticmethod
    def _default_encode(strategy: Any) -> str:
        return json.dumps(strategy, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _default_decode(payload: str) -> Any:
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload


def get_shared_smart_cache(
    db_path: str = "smart_cache.sqlite3",
    *,
    min_success_rate: float = 0.50,
    decay_grace_days: float = 7.0,
    decay_half_life_days: float = 7.0,
    busy_timeout_ms: int = 5000,
    max_lock_retries: int = 4,
    lock_retry_base_sec: float = 0.05,
    strategy_encoder: Optional[Callable[[Any], str]] = None,
    strategy_decoder: Optional[Callable[[str], Any]] = None,
) -> SmartCache:
    global _GLOBAL_CACHE
    with _GLOBAL_CACHE_LOCK:
        if _GLOBAL_CACHE is None:
            _GLOBAL_CACHE = SmartCache(
                db_path=db_path,
                min_success_rate=min_success_rate,
                decay_grace_days=decay_grace_days,
                decay_half_life_days=decay_half_life_days,
                busy_timeout_ms=busy_timeout_ms,
                max_lock_retries=max_lock_retries,
                lock_retry_base_sec=lock_retry_base_sec,
                strategy_encoder=strategy_encoder,
                strategy_decoder=strategy_decoder,
            )
        return _GLOBAL_CACHE
