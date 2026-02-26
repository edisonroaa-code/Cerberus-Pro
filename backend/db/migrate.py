"""Run PostgreSQL migrations for Cerberus backend."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from db.postgres_store import PostgresStore


def main() -> int:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    store = PostgresStore.from_env(database_url)
    if not store:
        print("PostgreSQL migration skipped: DATABASE_URL invalid or psycopg missing")
        return 1
    store.ensure_schema()
    print("PostgreSQL migrations applied successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
