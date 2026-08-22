"""Persistence API for SENTRA.

PostgreSQL is the production backend. SQLite remains a development convenience
behind the same public functions so the offline demo can run without hosted
credentials. SQL adaptation and connection lifecycle are confined to this file.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from database.pool import close_database_pool, get_database_pool, open_database_pool
from db_config import get_database_settings


class DatabaseNotInitializedError(RuntimeError):
    """Raised when PostgreSQL migrations have not been applied."""


def database_backend() -> str:
    return get_database_settings().backend


def _adapt_sql(sql: str) -> str:
    """Translate the module's neutral qmark placeholders for Psycopg."""
    if get_database_settings().is_postgresql:
        return sql.replace("?", "%s")
    return sql


def _execute(cursor, sql: str, params: Iterable[Any] = ()):
    return cursor.execute(_adapt_sql(sql), tuple(params))


@contextmanager
def _managed_cursor(conn) -> Iterator[Any]:
    """Provide the same cursor cleanup semantics on Psycopg and sqlite3."""
    cursor = conn.cursor()
    try:
        yield cursor
    finally:
        cursor.close()


@contextmanager
def get_db_connection() -> Iterator[Any]:
    """Yield a managed connection and always return/close it."""
    settings = get_database_settings()
    if settings.is_postgresql:
        with get_database_pool().connection() as conn:
            yield conn
        return

    conn = sqlite3.connect(str(settings.sqlite_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _transaction() -> Iterator[Any]:
    """Yield one cursor inside a commit-on-success, rollback-on-error unit."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            if get_database_settings().is_postgresql:
                with conn.transaction():
                    yield cursor
            else:
                try:
                    yield cursor
                except Exception:
                    conn.rollback()
                    raise
                else:
                    conn.commit()
        finally:
            cursor.close()


def _init_sqlite_schema() -> None:
    """Maintain the optional local SQLite fallback; production uses migrations."""
    with _transaction() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                severity TEXT,
                threat_type TEXT,
                affected_user TEXT,
                affected_host TEXT,
                source_ip TEXT,
                status TEXT DEFAULT 'open',
                analyst_label TEXT DEFAULT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                label TEXT NOT NULL,
                reason TEXT,
                analyst_notes TEXT,
                source_ip TEXT,
                threat_type TEXT,
                affected_user TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES incidents(event_id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT,
                severity TEXT,
                incident_count INTEGER,
                furthest_stage TEXT,
                progression_pct INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS response_approvals (
                approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                action TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                note TEXT,
                FOREIGN KEY (event_id) REFERENCES incidents(event_id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS determinations (
                subject_key TEXT PRIMARY KEY,
                determined_at TEXT NOT NULL
            )
            """
        )
        existing_columns = {
            row[1] for row in cursor.execute("PRAGMA table_info(incidents)").fetchall()
        }
        if "analyst_label" not in existing_columns:
            cursor.execute(
                "ALTER TABLE incidents ADD COLUMN analyst_label TEXT DEFAULT NULL"
            )


def _verify_postgresql_schema() -> None:
    required = {
        "incidents", "analyst_feedback", "campaigns", "response_approvals",
        "determinations",
    }
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        cursor.execute(
            """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = ANY(%s)
                """,
            (list(required),),
        )
        present = {row["table_name"] for row in cursor.fetchall()}
    missing = sorted(required - present)
    if missing:
        raise DatabaseNotInitializedError(
            "PostgreSQL schema is not initialized. Run `python -m database.migrate` "
            f"before starting SENTRA. Missing tables: {', '.join(missing)}"
        )


def init_db() -> None:
    """Initialize SQLite locally or verify the migrated PostgreSQL schema."""
    settings = get_database_settings()
    if settings.is_postgresql:
        open_database_pool()
        _verify_postgresql_schema()
    else:
        _init_sqlite_schema()


def close_db() -> None:
    close_database_pool()


def check_database_health() -> bool:
    try:
        with get_db_connection() as conn, _managed_cursor(conn) as cursor:
            cursor.execute("SELECT 1")
            return cursor.fetchone() is not None
    except Exception:
        return False


def _incident_columns(event: dict) -> tuple[Any, ...] | None:
    event_id = event.get("event_id")
    if not event_id:
        return None
    raw_event = event.get("raw_event", {}) or {}
    ingestion = event.get("ingestion", {}) or {}
    detection = event.get("detection", {}) or {}
    dashboard = event.get("dashboard", {}) or {}
    final_report = event.get("final_report", {}) or {}
    timestamp = raw_event.get("timestamp") or ingestion.get("timestamp") or ""
    severity = detection.get("severity") or dashboard.get("severity") or "low"
    threat_type = detection.get("threat_type") or "unknown"
    affected_user = (
        dashboard.get("affected_user")
        or raw_event.get("affected_user")
        or raw_event.get("user")
        or "anonymous"
    )
    affected_host = (
        raw_event.get("affected_host")
        or raw_event.get("host")
        or raw_event.get("hostname")
        or "workstation"
    )
    source_ip = dashboard.get("source_ip") or raw_event.get("source_ip") or "N/A"
    status = str(final_report.get("status") or event.get("status") or "open").lower()
    return (
        event_id,
        timestamp,
        severity,
        threat_type,
        affected_user,
        affected_host,
        source_ip,
        status,
        json.dumps(event),
    )


def save_incident_with_cursor(cursor, event: dict, overwrite: bool = True) -> None:
    values = _incident_columns(event)
    if values is None:
        return
    if overwrite:
        _execute(
            cursor,
            """
            INSERT INTO incidents
                (event_id, timestamp, severity, threat_type, affected_user,
                 affected_host, source_ip, status, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                timestamp=excluded.timestamp,
                severity=excluded.severity,
                threat_type=excluded.threat_type,
                affected_user=excluded.affected_user,
                affected_host=excluded.affected_host,
                source_ip=excluded.source_ip,
                status=excluded.status,
                payload=excluded.payload
            """,
            values,
        )
    else:
        _execute(
            cursor,
            """
            INSERT INTO incidents
                (event_id, timestamp, severity, threat_type, affected_user,
                 affected_host, source_ip, status, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO NOTHING
            """,
            values,
        )


def save_incident(event: dict) -> None:
    with _transaction() as cursor:
        save_incident_with_cursor(cursor, event)


def _replace_campaigns_with_cursor(cursor, campaigns: list[dict]) -> int:
    cursor.execute("DELETE FROM campaigns")
    now = datetime.now(UTC).isoformat()
    for campaign in campaigns:
        _execute(
            cursor,
            """
            INSERT INTO campaigns
                (campaign_id, name, severity, incident_count, furthest_stage,
                 progression_pct, first_seen, last_seen, payload, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign.get("campaign_id"),
                campaign.get("name"),
                campaign.get("severity"),
                campaign.get("incident_count"),
                campaign.get("furthest_stage"),
                campaign.get("progression_pct"),
                campaign.get("first_seen"),
                campaign.get("last_seen"),
                json.dumps(campaign),
                now,
            ),
        )
    return len(campaigns)


def persist_pipeline_results(events: list[dict], campaigns: list[dict]) -> None:
    """Atomically upsert every incident and replace the campaign conclusion."""
    with _transaction() as cursor:
        for event in events:
            save_incident_with_cursor(cursor, event)
        _replace_campaigns_with_cursor(cursor, campaigns)


def _decode_payload(value: Any) -> dict | None:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def get_all_incidents() -> list[dict]:
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        cursor.execute("SELECT payload FROM incidents ORDER BY timestamp DESC")
        rows = cursor.fetchall()
    return [payload for row in rows if (payload := _decode_payload(row["payload"]))]


def get_incident(event_id: str) -> dict | None:
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        _execute(cursor, "SELECT payload FROM incidents WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()
    return _decode_payload(row["payload"]) if row else None


def update_incident_status(event_id: str, status: str) -> bool:
    if status not in {"open", "closed", "investigating"}:
        raise ValueError("Unsupported incident status.")
    with _transaction() as cursor:
        lock = " FOR UPDATE" if get_database_settings().is_postgresql else ""
        _execute(
            cursor,
            f"SELECT payload FROM incidents WHERE event_id = ?{lock}",
            (event_id,),
        )
        row = cursor.fetchone()
        if not row:
            return False
        event = _decode_payload(row["payload"])
        if event is None:
            return False
        event.setdefault("final_report", {})["status"] = status
        event["status"] = status
        if isinstance(event.get("dashboard"), dict):
            event["dashboard"]["status"] = status
        _execute(
            cursor,
            "UPDATE incidents SET status = ?, payload = ? WHERE event_id = ?",
            (status, json.dumps(event), event_id),
        )
    return True


def clear_all_incidents() -> None:
    with _transaction() as cursor:
        # Explicit dependent deletes keep old SQLite databases (created before
        # foreign keys were added) behaviorally consistent with PostgreSQL.
        cursor.execute("DELETE FROM analyst_feedback")
        cursor.execute("DELETE FROM response_approvals")
        cursor.execute("DELETE FROM incidents")


def clear_incidents_and_campaigns() -> None:
    with _transaction() as cursor:
        cursor.execute("DELETE FROM analyst_feedback")
        cursor.execute("DELETE FROM response_approvals")
        cursor.execute("DELETE FROM campaigns")
        cursor.execute("DELETE FROM incidents")


def save_feedback(
    event_id: str,
    label: str,
    reason: str,
    analyst_notes: str,
    source_ip: str | None = None,
    threat_type: str | None = None,
    affected_user: str | None = None,
) -> bool:
    with _transaction() as cursor:
        _execute(
            cursor,
            """
            INSERT INTO analyst_feedback
                (event_id, label, reason, analyst_notes, source_ip, threat_type,
                 affected_user, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                label,
                reason,
                analyst_notes,
                source_ip,
                threat_type,
                affected_user,
                datetime.now(UTC).isoformat(),
            ),
        )
        _execute(
            cursor,
            "UPDATE incidents SET analyst_label = ? WHERE event_id = ?",
            (label, event_id),
        )
    return True


def get_suppression_list() -> list[dict]:
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        cursor.execute(
            """
            SELECT DISTINCT source_ip, threat_type, affected_user
            FROM analyst_feedback
            WHERE label = 'false_positive'
              AND (source_ip IS NOT NULL OR threat_type IS NOT NULL OR affected_user IS NOT NULL)
            """
        )
        rows = cursor.fetchall()
    return [
        {
            "source_ip": row["source_ip"],
            "threat_type": row["threat_type"],
            "affected_user": row["affected_user"],
        }
        for row in rows
    ]


def get_feedback_for_incident(event_id: str) -> list[dict]:
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        _execute(
            cursor,
            """
                SELECT feedback_id, event_id, label, reason, analyst_notes,
                       source_ip, threat_type, affected_user, created_at
                FROM analyst_feedback
                WHERE event_id = ?
                ORDER BY created_at DESC
                """,
            (event_id,),
        )
        rows = cursor.fetchall()
    return [dict(row) for row in rows]


def replace_campaigns(campaigns: list[dict]) -> int:
    with _transaction() as cursor:
        return _replace_campaigns_with_cursor(cursor, campaigns)


def get_all_campaigns() -> list[dict]:
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        cursor.execute(
            "SELECT payload FROM campaigns "
            "ORDER BY progression_pct DESC, incident_count DESC"
        )
        rows = cursor.fetchall()
    return [payload for row in rows if (payload := _decode_payload(row["payload"]))]


def get_campaign(campaign_id: str) -> dict | None:
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        _execute(
            cursor,
            "SELECT payload FROM campaigns WHERE campaign_id = ?",
            (campaign_id,),
        )
        row = cursor.fetchone()
    return _decode_payload(row["payload"]) if row else None


def determination_time(subject_key: str, proposed: str) -> str:
    """Persist and return the subject's first regulatory determination time."""
    with _transaction() as cursor:
        _execute(
            cursor,
            """
            INSERT INTO determinations (subject_key, determined_at)
            VALUES (?, ?)
            ON CONFLICT(subject_key) DO NOTHING
            """,
            (subject_key, proposed),
        )
        _execute(
            cursor,
            "SELECT determined_at FROM determinations WHERE subject_key = ?",
            (subject_key,),
        )
        row = cursor.fetchone()
        return str(row["determined_at"]) if row else proposed


def clear_determinations() -> None:
    """Forget determination anchors for tests and explicit demo resets."""
    with _transaction() as cursor:
        cursor.execute("DELETE FROM determinations")


def request_approval(event_id: str, action: str) -> int:
    with _transaction() as cursor:
        if get_database_settings().is_postgresql:
            cursor.execute(
                """
                INSERT INTO response_approvals
                    (event_id, action, state, requested_at)
                VALUES (%s, %s, 'pending', %s)
                RETURNING approval_id
                """,
                (event_id, action, datetime.now(UTC).isoformat()),
            )
            return int(cursor.fetchone()["approval_id"])
        cursor.execute(
            """
            INSERT INTO response_approvals (event_id, action, state, requested_at)
            VALUES (?, ?, 'pending', ?)
            """,
            (event_id, action, datetime.now(UTC).isoformat()),
        )
        return int(cursor.lastrowid)


def decide_approval(
    approval_id: int,
    approve: bool,
    decided_by: str,
    note: str = "",
) -> bool:
    """Atomically transition exactly one still-pending approval."""
    with _transaction() as cursor:
        _execute(
            cursor,
            """
            UPDATE response_approvals
            SET state = ?, decided_at = ?, decided_by = ?, note = ?
            WHERE approval_id = ? AND state = 'pending'
            """,
            (
                "approved" if approve else "rejected",
                datetime.now(UTC).isoformat(),
                decided_by or "analyst",
                note,
                approval_id,
            ),
        )
        return cursor.rowcount == 1


def get_approvals(
    event_id: str | None = None,
    state: str | None = None,
) -> list[dict]:
    sql = "SELECT * FROM response_approvals"
    clauses: list[str] = []
    params: list[Any] = []
    if event_id:
        clauses.append("event_id = ?")
        params.append(event_id)
    if state:
        clauses.append("state = ?")
        params.append(state)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY approval_id DESC"
    with get_db_connection() as conn, _managed_cursor(conn) as cursor:
        _execute(cursor, sql, params)
        rows = cursor.fetchall()
    return [dict(row) for row in rows]
