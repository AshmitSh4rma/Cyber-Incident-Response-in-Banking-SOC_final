"""Persistence contract tests using an isolated SQLite development database."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient

import db_manager
from db_config import (
    DatabaseConfigurationError,
    get_database_settings,
    reset_database_settings_cache,
)


def _event(event_id: str, severity: str = "high") -> dict:
    return {
        "event_id": event_id,
        "raw_event": {
            "timestamp": "2026-08-22T02:21:44Z",
            "source_ip": "203.0.113.55",
            "affected_host": "dmz-web-01",
            "affected_user": "svc_payments",
        },
        "dashboard": {
            "severity": severity,
            "source_ip": "203.0.113.55",
            "affected_host": "dmz-web-01",
            "affected_user": "svc_payments",
        },
        "detection": {
            "label": "malicious",
            "severity": severity,
            "threat_type": "web_attack",
        },
        "final_report": {"status": "open"},
    }


def _campaign(campaign_id: str = "CMP-001") -> dict:
    return {
        "campaign_id": campaign_id,
        "name": "Test campaign",
        "severity": "high",
        "incident_count": 1,
        "furthest_stage": "Initial Access",
        "progression_pct": 20,
        "first_seen": "2026-08-22T02:21:44Z",
        "last_seen": "2026-08-22T02:21:44Z",
        "incident_ids": ["evt-1"],
    }


def test_production_requires_postgresql(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    reset_database_settings_cache()
    with pytest.raises(DatabaseConfigurationError, match="Production requires PostgreSQL"):
        get_database_settings()
    reset_database_settings_cache()


def test_legacy_postgres_scheme_is_normalized_without_losing_options(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DB_BACKEND", "postgresql")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://user:password@example.invalid/sentra?sslmode=require&channel_binding=require",
    )
    reset_database_settings_cache()
    settings = get_database_settings()
    assert settings.database_url == (
        "postgresql://user:password@example.invalid/sentra"
        "?sslmode=require&channel_binding=require"
    )
    reset_database_settings_cache()


@pytest.fixture()
def isolated_database(tmp_path, monkeypatch):
    db_manager.close_db()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SQLITE_DATABASE_PATH", str(tmp_path / "sentra-test.sqlite3"))
    reset_database_settings_cache()
    db_manager.init_db()
    yield
    db_manager.close_db()
    reset_database_settings_cache()


def test_incident_insert_list_retrieve_update_and_upsert(isolated_database):
    db_manager.save_incident(_event("evt-1"))
    assert db_manager.get_incident("evt-1")["detection"]["severity"] == "high"
    assert [item["event_id"] for item in db_manager.get_all_incidents()] == ["evt-1"]

    updated = _event("evt-1", severity="critical")
    db_manager.save_incident(updated)
    assert len(db_manager.get_all_incidents()) == 1
    assert db_manager.get_incident("evt-1")["detection"]["severity"] == "critical"

    assert db_manager.update_incident_status("evt-1", "investigating") is True
    stored = db_manager.get_incident("evt-1")
    assert stored["status"] == "investigating"
    assert stored["final_report"]["status"] == "investigating"
    assert db_manager.update_incident_status("missing", "closed") is False


def test_feedback_history_and_suppression_rules(isolated_database):
    db_manager.save_incident(_event("evt-1"))
    assert db_manager.save_feedback(
        "evt-1",
        "false_positive",
        "authorized_scan",
        "Change window verified",
        source_ip="203.0.113.55",
        threat_type="web_attack",
        affected_user="svc_payments",
    )
    feedback = db_manager.get_feedback_for_incident("evt-1")
    assert len(feedback) == 1
    assert feedback[0]["label"] == "false_positive"
    assert db_manager.get_suppression_list() == [
        {
            "source_ip": "203.0.113.55",
            "threat_type": "web_attack",
            "affected_user": "svc_payments",
        }
    ]


def test_campaign_save_retrieve_and_replace(isolated_database):
    assert db_manager.replace_campaigns([_campaign()]) == 1
    assert db_manager.get_campaign("CMP-001")["name"] == "Test campaign"
    assert len(db_manager.get_all_campaigns()) == 1
    db_manager.replace_campaigns([_campaign("CMP-002")])
    assert db_manager.get_campaign("CMP-001") is None
    assert [item["campaign_id"] for item in db_manager.get_all_campaigns()] == ["CMP-002"]


def test_approval_transitions_only_once(isolated_database):
    db_manager.save_incident(_event("evt-1"))
    approval_id = db_manager.request_approval("evt-1", "Isolate host")
    assert db_manager.get_approvals(event_id="evt-1", state="pending")[0]["approval_id"] == approval_id
    assert db_manager.decide_approval(approval_id, True, "analyst-a") is True
    assert db_manager.decide_approval(approval_id, False, "analyst-b") is False
    assert db_manager.get_approvals(event_id="evt-1")[0]["state"] == "approved"


def test_rejection_and_concurrent_decision_are_atomic(isolated_database):
    db_manager.save_incident(_event("evt-1"))
    rejection_id = db_manager.request_approval("evt-1", "Disable account")
    assert db_manager.decide_approval(rejection_id, False, "analyst-a") is True
    assert db_manager.get_approvals(event_id="evt-1")[0]["state"] == "rejected"

    approval_id = db_manager.request_approval("evt-1", "Isolate host")
    barrier = Barrier(2)

    def decide(approve: bool) -> bool:
        barrier.wait()
        return db_manager.decide_approval(approval_id, approve, "concurrent-analyst")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(decide, (True, False)))
    assert sorted(results) == [False, True]


def test_incident_delete_removes_dependent_records(isolated_database):
    db_manager.save_incident(_event("evt-1"))
    db_manager.save_feedback("evt-1", "true_positive", "confirmed", "")
    db_manager.request_approval("evt-1", "Isolate host")
    db_manager.clear_all_incidents()
    assert db_manager.get_all_incidents() == []
    assert db_manager.get_feedback_for_incident("evt-1") == []
    assert db_manager.get_approvals(event_id="evt-1") == []


def test_pipeline_persistence_rolls_back_all_writes(isolated_database):
    db_manager.save_incident(_event("existing"))
    db_manager.replace_campaigns([_campaign("CMP-OLD")])
    duplicate_campaigns = [_campaign("CMP-DUP"), _campaign("CMP-DUP")]

    with pytest.raises(Exception):
        db_manager.persist_pipeline_results([_event("new")], duplicate_campaigns)

    assert db_manager.get_incident("new") is None
    assert db_manager.get_incident("existing") is not None
    assert db_manager.get_campaign("CMP-OLD") is not None
    assert db_manager.get_campaign("CMP-DUP") is None


def test_fastapi_health_and_incident_contract(isolated_database):
    from api_server import app

    db_manager.save_incident(_event("evt-api"))
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {
            "status": "ok",
            "database": "connected",
            "database_backend": "sqlite",
        }
        response = client.get("/api/incidents/evt-api")
        assert response.status_code == 200
        assert response.json()["event_id"] == "evt-api"
