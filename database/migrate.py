"""Apply ordered PostgreSQL SQL migrations exactly once."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from database.pool import close_database_pool, get_database_pool, open_database_pool
from db_config import get_database_settings

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql"))


def run_migrations() -> list[str]:
    settings = get_database_settings()
    if not settings.is_postgresql:
        raise RuntimeError(
            "PostgreSQL migrations require DB_BACKEND=postgresql and DATABASE_URL."
        )

    open_database_pool()
    applied_now: list[str] = []
    pool = get_database_pool()
    with pool.connection() as conn, conn.transaction(), conn.cursor() as cursor:
        cursor.execute(
            """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version TEXT PRIMARY KEY,
                        checksum TEXT NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
        )
        cursor.execute("SELECT version, checksum FROM schema_migrations")
        applied = {row["version"]: row["checksum"] for row in cursor.fetchall()}

        for path in _migration_files():
            version = path.name.split("_", 1)[0]
            sql = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            if version in applied:
                if applied[version] != checksum:
                    raise RuntimeError(
                        f"Migration {version} was modified after being applied."
                    )
                continue
            # Migrations intentionally contain plain DDL only. Execute
            # statements individually so hosted pools that use extended
            # query mode never receive a multi-command prepared query.
            for statement in (part.strip() for part in sql.split(";")):
                if statement:
                    cursor.execute(statement)
            cursor.execute(
                "INSERT INTO schema_migrations (version, checksum) VALUES (%s, %s)",
                (version, checksum),
            )
            applied_now.append(path.name)
    return applied_now


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        applied = run_migrations()
        if applied:
            print("Applied PostgreSQL migrations:")
            for name in applied:
                print(f"  - {name}")
        else:
            print("PostgreSQL schema is already current.")
        return 0
    finally:
        close_database_pool()


if __name__ == "__main__":
    raise SystemExit(main())
