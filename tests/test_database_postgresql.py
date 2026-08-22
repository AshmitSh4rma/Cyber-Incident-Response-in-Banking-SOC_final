"""Guarded PostgreSQL integration tests.

The suite is skipped unless TEST_DATABASE_URL is supplied. It creates a unique
schema and drops only that schema, never the database or public schema.
"""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)


pytestmark = pytest.mark.postgresql


def _url_with_search_path(url: str, schema: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["options"] = f"-csearch_path={schema}"
    # Neon pooler endpoints reject ``search_path`` as a startup option. The
    # matching direct endpoint accepts it and is appropriate for this isolated
    # migration-test session.
    netloc = parts.netloc.replace("-pooler.", ".", 1)
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))


def _event(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "raw_event": {"timestamp": "2026-08-22T00:00:00Z", "source_ip": "198.51.100.4"},
        "dashboard": {"severity": "high", "source_ip": "198.51.100.4"},
        "detection": {"label": "malicious", "severity": "high", "threat_type": "web_attack"},
        "final_report": {"status": "open"},
    }


def _campaign(campaign_id: str) -> dict:
    return {
        "campaign_id": campaign_id,
        "name": "PostgreSQL integration campaign",
        "severity": "high",
        "incident_count": 1,
        "furthest_stage": "Initial Access",
        "progression_pct": 20,
        "first_seen": "2026-08-22T00:00:00Z",
        "last_seen": "2026-08-22T00:00:00Z",
        "incident_ids": ["pg-event"],
    }


@pytest.fixture(scope="module")
def postgres_database():
    base_url = os.getenv("TEST_DATABASE_URL", "").strip()
    if not base_url:
        pytest.skip("TEST_DATABASE_URL is not configured")
    if not base_url.startswith(("postgres://", "postgresql://")):
        pytest.fail("TEST_DATABASE_URL must be a PostgreSQL URL")

    import psycopg
    from psycopg import sql

    schema = f"sentra_test_{uuid.uuid4().hex}"
    with psycopg.connect(base_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    previous = {key: os.environ.get(key) for key in ("DATABASE_URL", "DB_BACKEND", "ENVIRONMENT")}
    os.environ["DATABASE_URL"] = _url_with_search_path(base_url, schema)
    os.environ["DB_BACKEND"] = "postgresql"
    os.environ["ENVIRONMENT"] = "test"

    from db_config import reset_database_settings_cache
    import db_manager
    from database.migrate import run_migrations

    reset_database_settings_cache()
    db_manager.close_db()
    run_migrations()
    db_manager.init_db()
    try:
        yield db_manager
    finally:
        db_manager.close_db()
        reset_database_settings_cache()
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        with psycopg.connect(base_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_postgresql_complete_persistence_contract(postgres_database):
    db = postgres_database
    db.persist_pipeline_results([_event("pg-event")], [_campaign("PG-CMP")])
    assert db.get_incident("pg-event")["event_id"] == "pg-event"
    assert db.get_all_campaigns()[0]["campaign_id"] == "PG-CMP"
    assert db.update_incident_status("pg-event", "investigating") is True

    db.save_feedback(
        "pg-event", "false_positive", "authorized", "verified",
        source_ip="198.51.100.4", threat_type="web_attack",
    )
    assert db.get_feedback_for_incident("pg-event")[0]["label"] == "false_positive"
    assert db.get_suppression_list()[0]["source_ip"] == "198.51.100.4"

    approval_id = db.request_approval("pg-event", "Isolate host")
    assert db.decide_approval(approval_id, True, "analyst-a") is True
    assert db.decide_approval(approval_id, False, "analyst-b") is False


def test_postgresql_concurrent_approval_transition(postgres_database):
    db = postgres_database
    approval_id = db.request_approval("pg-event", "Disable account")
    barrier = Barrier(2)

    def decide(approve: bool) -> bool:
        barrier.wait()
        return db.decide_approval(approval_id, approve, "concurrent")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(decide, (True, False)))
    assert sorted(results) == [False, True]


def test_postgresql_transaction_rollback_and_fk_cascade(postgres_database):
    db = postgres_database
    with pytest.raises(Exception):
        db.persist_pipeline_results(
            [_event("must-rollback")],
            [_campaign("DUP"), _campaign("DUP")],
        )
    assert db.get_incident("must-rollback") is None
    assert db.get_campaign("PG-CMP") is not None

    db.clear_all_incidents()
    assert db.get_all_incidents() == []
    assert db.get_feedback_for_incident("pg-event") == []
    assert db.get_approvals(event_id="pg-event") == []
