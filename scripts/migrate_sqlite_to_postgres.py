"""One-time, non-destructive SQLite to PostgreSQL data migration.

Apply PostgreSQL schema migrations first. Existing destination rows are upserted;
the utility never deletes destination data and opens SQLite in read-only mode.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Iterable

from db_config import get_database_settings
from database.pool import close_database_pool, get_database_pool, open_database_pool


TABLES = ("incidents", "campaigns", "analyst_feedback", "response_approvals")


def _source_rows(conn: sqlite3.Connection, table: str) -> list[sqlite3.Row]:
    return conn.execute(f'SELECT * FROM "{table}"').fetchall()


def _execute_many(cursor, sql: str, rows: Iterable[tuple]) -> None:
    for row in rows:
        cursor.execute(sql, row)


def migrate(source: Path) -> dict[str, tuple[int, int]]:
    settings = get_database_settings()
    if not settings.is_postgresql:
        raise RuntimeError(
            "Destination must be PostgreSQL. Set DB_BACKEND=postgresql and DATABASE_URL."
        )
    if not source.is_file():
        raise FileNotFoundError(f"SQLite source not found: {source}")

    sqlite_url = f"file:{source.resolve().as_posix()}?mode=ro"
    source_conn = sqlite3.connect(sqlite_url, uri=True)
    source_conn.row_factory = sqlite3.Row
    source_counts: dict[str, int] = {}

    open_database_pool()
    try:
        source_data = {table: _source_rows(source_conn, table) for table in TABLES}
        source_counts = {table: len(rows) for table, rows in source_data.items()}

        with get_database_pool().connection() as destination:
            with destination.transaction():
                with destination.cursor() as cursor:
                    _execute_many(
                        cursor,
                        """
                        INSERT INTO incidents
                            (event_id, timestamp, severity, threat_type, affected_user,
                             affected_host, source_ip, status, analyst_label, payload)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (event_id) DO UPDATE SET
                            timestamp=excluded.timestamp,
                            severity=excluded.severity,
                            threat_type=excluded.threat_type,
                            affected_user=excluded.affected_user,
                            affected_host=excluded.affected_host,
                            source_ip=excluded.source_ip,
                            status=excluded.status,
                            analyst_label=excluded.analyst_label,
                            payload=excluded.payload
                        """,
                        (
                            tuple(row[key] for key in (
                                "event_id", "timestamp", "severity", "threat_type",
                                "affected_user", "affected_host", "source_ip", "status",
                                "analyst_label", "payload",
                            ))
                            for row in source_data["incidents"]
                        ),
                    )
                    _execute_many(
                        cursor,
                        """
                        INSERT INTO campaigns
                            (campaign_id, name, severity, incident_count, furthest_stage,
                             progression_pct, first_seen, last_seen, payload, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (campaign_id) DO UPDATE SET
                            name=excluded.name,
                            severity=excluded.severity,
                            incident_count=excluded.incident_count,
                            furthest_stage=excluded.furthest_stage,
                            progression_pct=excluded.progression_pct,
                            first_seen=excluded.first_seen,
                            last_seen=excluded.last_seen,
                            payload=excluded.payload,
                            updated_at=excluded.updated_at
                        """,
                        (
                            tuple(row[key] for key in (
                                "campaign_id", "name", "severity", "incident_count",
                                "furthest_stage", "progression_pct", "first_seen", "last_seen",
                                "payload", "updated_at",
                            ))
                            for row in source_data["campaigns"]
                        ),
                    )
                    _execute_many(
                        cursor,
                        """
                        INSERT INTO analyst_feedback
                            (feedback_id, event_id, label, reason, analyst_notes, source_ip,
                             threat_type, affected_user, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (feedback_id) DO UPDATE SET
                            event_id=excluded.event_id,
                            label=excluded.label,
                            reason=excluded.reason,
                            analyst_notes=excluded.analyst_notes,
                            source_ip=excluded.source_ip,
                            threat_type=excluded.threat_type,
                            affected_user=excluded.affected_user,
                            created_at=excluded.created_at
                        """,
                        (
                            tuple(row[key] for key in (
                                "feedback_id", "event_id", "label", "reason", "analyst_notes",
                                "source_ip", "threat_type", "affected_user", "created_at",
                            ))
                            for row in source_data["analyst_feedback"]
                        ),
                    )
                    _execute_many(
                        cursor,
                        """
                        INSERT INTO response_approvals
                            (approval_id, event_id, action, state, requested_at, decided_at,
                             decided_by, note)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (approval_id) DO UPDATE SET
                            event_id=excluded.event_id,
                            action=excluded.action,
                            state=excluded.state,
                            requested_at=excluded.requested_at,
                            decided_at=excluded.decided_at,
                            decided_by=excluded.decided_by,
                            note=excluded.note
                        """,
                        (
                            tuple(row[key] for key in (
                                "approval_id", "event_id", "action", "state", "requested_at",
                                "decided_at", "decided_by", "note",
                            ))
                            for row in source_data["response_approvals"]
                        ),
                    )
                    for table, column in (
                        ("analyst_feedback", "feedback_id"),
                        ("response_approvals", "approval_id"),
                    ):
                        cursor.execute(
                            f"""
                            SELECT setval(
                                pg_get_serial_sequence('{table}', '{column}'),
                                COALESCE(MAX({column}), 1),
                                COUNT(*) > 0
                            )
                            FROM {table}
                            """
                        )

        with get_database_pool().connection() as destination:
            with destination.cursor() as cursor:
                destination_counts = {}
                for table in TABLES:
                    cursor.execute(f"SELECT COUNT(*) AS count FROM {table}")
                    destination_counts[table] = int(cursor.fetchone()["count"])
        return {
            table: (source_counts[table], destination_counts[table])
            for table in TABLES
        }
    finally:
        source_conn.close()
        close_database_pool()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "soc_incidents.db",
        help="SQLite source file (default: repository soc_incidents.db)",
    )
    args = parser.parse_args()
    comparisons = migrate(args.source)
    print("SQLite to PostgreSQL migration completed.")
    print("Rows (source -> destination):")
    for table, (source_count, destination_count) in comparisons.items():
        print(f"  {table}: {source_count} -> {destination_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
