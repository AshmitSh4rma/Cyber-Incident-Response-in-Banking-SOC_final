import contextlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "soc_incidents.db"

def get_db_connection():
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
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
            payload TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyst_feedback (
            feedback_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id      TEXT NOT NULL,
            label         TEXT NOT NULL,
            reason        TEXT,
            analyst_notes TEXT,
            source_ip     TEXT,
            threat_type   TEXT,
            affected_user TEXT,
            created_at    TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id     TEXT PRIMARY KEY,
            name            TEXT,
            severity        TEXT,
            incident_count  INTEGER,
            furthest_stage  TEXT,
            progression_pct INTEGER,
            first_seen      TEXT,
            last_seen       TEXT,
            payload         TEXT,
            updated_at      TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_approvals (
            approval_id  INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id     TEXT NOT NULL,
            action       TEXT NOT NULL,
            state        TEXT NOT NULL DEFAULT 'pending',
            requested_at TEXT NOT NULL,
            decided_at   TEXT,
            decided_by   TEXT,
            note         TEXT
        )
    """)
    conn.commit()

    # ── Schema Migration ─────────────────────────────────────────────────────
    # Safely add new columns to the incidents table if they don't exist yet.
    # This handles databases created before these columns were added.
    existing_columns = {row[1] for row in cursor.execute("PRAGMA table_info(incidents)")}
    if "analyst_label" not in existing_columns:
        cursor.execute("ALTER TABLE incidents ADD COLUMN analyst_label TEXT DEFAULT NULL")
        conn.commit()
        print("[db_manager] Migration: added analyst_label column to incidents table.")
    # ─────────────────────────────────────────────────────────────────────────

    conn.commit()
    conn.close()

def save_incident_with_cursor(cursor, event, overwrite=True):
    event_id = event.get("event_id")
    if not event_id:
        return

    raw_event = event.get("raw_event", {}) or {}
    ingestion = event.get("ingestion", {}) or {}
    detection = event.get("detection", {}) or {}
    dashboard = event.get("dashboard", {}) or {}
    final_report = event.get("final_report", {}) or {}

    timestamp = raw_event.get("timestamp") or ingestion.get("timestamp") or ""
    severity = detection.get("severity") or dashboard.get("severity") or "low"
    threat_type = detection.get("threat_type") or "unknown"
    affected_user = dashboard.get("affected_user") or raw_event.get("affected_user") or raw_event.get("user") or "anonymous"
    affected_host = raw_event.get("affected_host") or raw_event.get("host") or raw_event.get("hostname") or "workstation"
    source_ip = dashboard.get("source_ip") or raw_event.get("source_ip") or "N/A"
    # Normalise casing — seed data uses "Open" while pipeline output uses "open",
    # and the dashboard filters on the raw value in some views.
    status = str(final_report.get("status") or event.get("status") or "open").lower()

    payload = json.dumps(event)

    if overwrite:
        cursor.execute("""
            INSERT INTO incidents (event_id, timestamp, severity, threat_type, affected_user, affected_host, source_ip, status, payload)
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
        """, (event_id, timestamp, severity, threat_type, affected_user, affected_host, source_ip, status, payload))
    else:
        cursor.execute("""
            INSERT INTO incidents (event_id, timestamp, severity, threat_type, affected_user, affected_host, source_ip, status, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO NOTHING
        """, (event_id, timestamp, severity, threat_type, affected_user, affected_host, source_ip, status, payload))

def save_incident(event):
    conn = get_db_connection()
    cursor = conn.cursor()
    save_incident_with_cursor(cursor, event)
    conn.commit()
    conn.close()

def get_all_incidents():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT payload FROM incidents ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()

    incidents = []
    for row in rows:
        # A row whose JSON is corrupt is skipped rather than failing the whole
        # listing — one bad write should not blank the console.
        with contextlib.suppress(json.JSONDecodeError):
            incidents.append(json.loads(row["payload"]))
    return incidents

def get_incident(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT payload FROM incidents WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        try:
            return json.loads(row["payload"])
        except Exception:
            pass
    return None

def update_incident_status(event_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT payload FROM incidents WHERE event_id = ?", (event_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    try:
        event = json.loads(row["payload"])
    except Exception:
        conn.close()
        return False

    if "final_report" not in event or not isinstance(event["final_report"], dict):
        event["final_report"] = {}
    event["final_report"]["status"] = status
    event["status"] = status

    # Also sync dashboard representation if present
    if "dashboard" in event and isinstance(event["dashboard"], dict):
      event["dashboard"]["status"] = status

    payload = json.dumps(event)

    cursor.execute("""
        UPDATE incidents
        SET status = ?, payload = ?
        WHERE event_id = ?
    """, (status, payload, event_id))

    conn.commit()
    conn.close()
    return True

def clear_all_incidents():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# Analyst Feedback Functions
# ─────────────────────────────────────────

def save_feedback(event_id: str, label: str, reason: str, analyst_notes: str,
                  source_ip: str = None, threat_type: str = None, affected_user: str = None) -> bool:
    """
    Save analyst feedback for an incident label (TP/FP/FN/Escalated).
    Also updates the analyst_label column on the incident record.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    created_at = datetime.now(UTC).isoformat()

    cursor.execute("""
        INSERT INTO analyst_feedback (event_id, label, reason, analyst_notes, source_ip, threat_type, affected_user, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (event_id, label, reason, analyst_notes, source_ip, threat_type, affected_user, created_at))

    # Also stamp the analyst_label on the incident row for quick filtering
    cursor.execute("""
        UPDATE incidents SET analyst_label = ? WHERE event_id = ?
    """, (label, event_id))

    conn.commit()
    conn.close()
    return True


def get_suppression_list() -> list[dict]:
    """
    Returns all False Positive suppression rules derived from analyst feedback.
    Each rule contains: source_ip, threat_type, affected_user.
    The Layer 2 detection engine uses this to suppress matching events.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT source_ip, threat_type, affected_user
        FROM analyst_feedback
        WHERE label = 'false_positive'
          AND (source_ip IS NOT NULL OR threat_type IS NOT NULL OR affected_user IS NOT NULL)
    """)
    rows = cursor.fetchall()
    conn.close()

    rules = []
    for row in rows:
        rules.append({
            "source_ip":     row["source_ip"],
            "threat_type":   row["threat_type"],
            "affected_user": row["affected_user"],
        })
    return rules


def get_feedback_for_incident(event_id: str) -> list[dict]:
    """
    Returns the full analyst feedback history for a given incident.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT feedback_id, event_id, label, reason, analyst_notes, source_ip, threat_type, affected_user, created_at
        FROM analyst_feedback
        WHERE event_id = ?
        ORDER BY created_at DESC
    """, (event_id,))
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

# ─────────────────────────────────────────────────────────────────────────────
# CAMPAIGNS (Layer 2.5)
# ─────────────────────────────────────────────────────────────────────────────

def replace_campaigns(campaigns: list[dict]) -> int:
    """
    Replace the stored campaign set.

    Campaigns are a whole-batch conclusion, not a per-incident fact: adding one
    incident can merge two campaigns or split one. Recomputing and replacing is
    the only coherent option — incrementally patching rows would leave stale
    groupings behind.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM campaigns")
    now = datetime.now(UTC).isoformat()
    for c in campaigns:
        cursor.execute(
            """
            INSERT INTO campaigns
                (campaign_id, name, severity, incident_count, furthest_stage,
                 progression_pct, first_seen, last_seen, payload, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c.get("campaign_id"),
                c.get("name"),
                c.get("severity"),
                c.get("incident_count"),
                c.get("furthest_stage"),
                c.get("progression_pct"),
                c.get("first_seen"),
                c.get("last_seen"),
                json.dumps(c),
                now,
            ),
        )
    conn.commit()
    conn.close()
    return len(campaigns)


def get_all_campaigns() -> list[dict]:
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT payload FROM campaigns ORDER BY progression_pct DESC, incident_count DESC"
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        # A row whose JSON is corrupt is skipped rather than failing the whole
        # listing — one bad write should not blank the console.
        with contextlib.suppress(json.JSONDecodeError):
            out.append(json.loads(row["payload"]))
    return out


def get_campaign(campaign_id: str) -> dict | None:
    conn = get_db_connection()
    row = conn.execute(
        "SELECT payload FROM campaigns WHERE campaign_id = ?", (campaign_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    try:
        return json.loads(row["payload"])
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HUMAN-IN-THE-LOOP RESPONSE APPROVALS (Layer 6)
# ─────────────────────────────────────────────────────────────────────────────

def request_approval(event_id: str, action: str) -> int:
    """Queue a containment action for analyst sign-off. Returns the approval id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO response_approvals (event_id, action, state, requested_at)
        VALUES (?, ?, 'pending', ?)
        """,
        (event_id, action, datetime.now(UTC).isoformat()),
    )
    approval_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return approval_id


def decide_approval(approval_id: int, approve: bool, decided_by: str, note: str = "") -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
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
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return changed


def get_approvals(event_id: str | None = None, state: str | None = None) -> list[dict]:
    conn = get_db_connection()
    sql = "SELECT * FROM response_approvals"
    clauses, params = [], []
    if event_id:
        clauses.append("event_id = ?")
        params.append(event_id)
    if state:
        clauses.append("state = ?")
        params.append(state)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY approval_id DESC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]
