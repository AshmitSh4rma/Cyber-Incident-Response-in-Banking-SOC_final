"""Generate and seed the SENTRA chatbot evaluation dataset through the real pipeline."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from db_config import get_database_settings
from db_manager import close_db, get_all_incidents, init_db, persist_pipeline_results
from layer_1_feature_engineering.ingestion_orchestrator import process_json_text
from layer_2_detection.campaign_correlator import correlate_campaigns
from pipeline import run_full_pipeline


DATASET_TAG = "sentra_chatbot_eval_v1"
EVENT_COUNT = 200
DATASET_PATH = Path(__file__).resolve().parent / "test_data" / "synthetic_soc_eval_v1.json"


def _timestamp(anchor: datetime, days_ago: float, minute_offset: int = 0) -> str:
    value = anchor - timedelta(days=days_ago, minutes=minute_offset)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_dataset(anchor: datetime | None = None) -> list[dict[str, Any]]:
    """Return 200 deterministic-shape events anchored to generation time."""
    anchor = (anchor or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    events: list[dict[str, Any]] = []

    def add(
        scenario: str,
        days_ago: float,
        log_type: str,
        source_ip: str,
        destination_ip: str,
        action: str,
        *,
        user: str = "unattributed",
        host: str = "unknown",
        port: int = 443,
        protocol: str = "tcp",
        result: str = "success",
        **extra: Any,
    ) -> None:
        sequence = len(events) + 1
        event = {
            "event_id": f"SYN-V1-{sequence:04d}",
            "dataset_tag": DATASET_TAG,
            "scenario": scenario,
            "timestamp": _timestamp(anchor, days_ago, sequence % 47),
            "log_type": log_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "port": port,
            "protocol": protocol,
            "action": action,
            "affected_user": user,
            "affected_host": host,
            "result": result,
        }
        event.update(extra)
        events.append(event)

    users = ["a.sharma", "r.mehta", "svc-payments", "svc-backup", "administrator"]
    hosts = ["PAYMENTS-WS01", "FINANCE-WS04", "SOC-JUMP01", "DB-PAYMENTS-01", "WEB-PORTAL-01", "VPN-GW-01"]

    # Routine background activity: 80 events (40%).
    for i in range(30):
        add("benign_employee_login", 6.8 - (i * 0.22), "auth", f"10.10.1.{20 + i % 10}", "10.10.0.10", "login_success", user=users[i % 3], host=hosts[i % 3], result="success")
    for i in range(15):
        add("benign_https", 6.5 - (i * 0.39), "network", f"10.10.2.{30 + i}", "10.10.20.10", "allow", user=users[i % 4], host="WEB-PORTAL-01", bytes_out=3200 + i * 20, bytes_in=18000 + i * 100, protocol="https")
    for i in range(10):
        add("benign_dns", 5.8 - (i * 0.55), "network", f"10.10.3.{40 + i}", "10.10.0.53", "allow", user=users[i % 4], host=hosts[i % 4], port=53, protocol="udp", query_type="A")
    for i in range(10):
        add("scheduled_backup", 6.0 - (i * 0.62), "network", "10.10.40.20", "10.10.40.30", "allow", user="svc-backup", host="DB-PAYMENTS-01", port=2049, protocol="tcp", bytes_out=25000000 + i * 100000, change_ticket="CHG-SYNTH-BACKUP")
    for i in range(10):
        add("expected_database_access", 5.5 - (i * 0.52), "network", "10.10.30.12", "10.10.40.11", "allow", user="svc-payments", host="DB-PAYMENTS-01", port=5432, protocol="tcp", query_category="routine_transaction_batch")
    for i in range(5):
        add("benign_iot_telemetry", 4.0 - (i * 0.7), "iot", f"192.168.50.{10 + i}", "10.10.60.5", "telemetry", host=f"ATM-SENSOR-{i + 1:02d}", port=8883, protocol="mqtt", device_id=f"ATM-SENSOR-{i + 1:02d}", device_type="environment_sensor", sensor_reading=22.1 + i / 10, telemetry_value="normal")

    # A: password spray and suspicious success (20).
    spray_users = ["a.sharma", "r.mehta", "administrator", "svc-payments", "svc-backup"]
    for i in range(18):
        add("password_spray", 0.82 - i * 0.012, "auth", "198.51.100.23", "10.10.0.20", "failed_login", user=spray_users[i % len(spray_users)], host="VPN-GW-01", port=443, protocol="https", result="failure")
    add("password_spray", 0.58, "auth", "198.51.100.23", "10.10.0.20", "credential_abuse", user="a.sharma", host="VPN-GW-01", result="success")
    add("password_spray", 0.55, "auth", "198.51.100.23", "10.10.10.21", "privilege_escalation", user="a.sharma", host="PAYMENTS-WS01", result="success")

    # B: suspicious account use (10).
    for i in range(10):
        add("suspicious_account_use", 3.5 - i * 0.08, "auth", "203.0.113.41", f"10.10.10.{21 + i % 3}", "credential_abuse" if i < 8 else "privilege_escalation", user="r.mehta", host=["FINANCE-WS04", "SOC-JUMP01", "DB-PAYMENTS-01"][i % 3], result="success", admin_activity=i >= 6)

    # C: reconnaissance across hosts and services (15).
    scan_ports = [22, 80, 443, 445, 3389, 5432, 8080, 8443]
    for i in range(15):
        add("network_reconnaissance", 1.8 - i * 0.025, "network", "192.0.2.77", f"10.10.20.{10 + i % 5}", "port_scan", host=["WEB-PORTAL-01", "VPN-GW-01", "SOC-JUMP01"][i % 3], port=scan_ports[i % len(scan_ports)], protocol="tcp", result="blocked")

    # D: non-actionable synthetic web probing (15).
    web_markers = ["synthetic_sql_injection_indicator", "synthetic_path_traversal_indicator", "synthetic_auth_probe_indicator"]
    for i in range(15):
        add("web_application_probing", 2.6 - i * 0.04, "web", "203.0.113.88", "10.10.20.10", "web_attack" if i % 3 else "suspicious_request", host="WEB-PORTAL-01", user="anonymous", port=443, protocol="https", result="blocked", url=f"/synthetic/security-test/{i}", http_method="POST" if i % 2 else "GET", http_status=403, attack_pattern=web_markers[i % len(web_markers)])

    # E: internal lateral movement (12).
    lateral_hosts = [("10.10.10.21", "10.10.10.24", "FINANCE-WS04"), ("10.10.10.24", "10.10.30.5", "SOC-JUMP01"), ("10.10.30.5", "10.10.40.11", "DB-PAYMENTS-01")]
    for i in range(12):
        src, dst, host = lateral_hosts[i % 3]
        add("lateral_movement", 1.2 - i * 0.025, "auth", src, dst, "lateral_movement", user="a.sharma", host=host, port=[445, 3389, 5985][i % 3], protocol="tcp", result="success", remote_service="synthetic_remote_admin_signal")

    # F: sensitive database activity (10).
    for i in range(10):
        add("sensitive_database_access", 0.95 - i * 0.035, "network", "10.10.30.5", "10.10.40.11", "credential_abuse" if i < 7 else "privilege_escalation", user="a.sharma", host="DB-PAYMENTS-01", port=5432, protocol="tcp", result="success", query_category="synthetic_high_volume_sensitive_access", records_touched=50000 + i * 5000)

    # G: possible exfiltration indicators (10).
    for i in range(10):
        add("possible_data_exfiltration", 0.45 - i * 0.02, "network", "10.10.40.11", "203.0.113.200", "data_exfiltration", user="a.sharma", host="DB-PAYMENTS-01", port=443, protocol="https", bytes_out=60000000 + i * 5000000, duration_ms=240000 + i * 10000, result="allowed")

    # H: IoT/device anomaly (10).
    for i in range(10):
        add("iot_device_anomaly", 4.8 - i * 0.13, "iot", "192.0.2.145", f"192.168.50.{10 + i % 3}", "credential_abuse" if i < 5 else "beaconing", user="device-admin", host=f"ATM-SENSOR-{1 + i % 3:02d}", port=23 if i < 5 else 8883, protocol="telnet" if i < 5 else "mqtt", device_id=f"ATM-SENSOR-{1 + i % 3:02d}", device_type="environment_sensor", telemetry_value="unexpected_peer", result="blocked")

    # I: unusual but explicitly approved maintenance noise (8).
    for i in range(8):
        add("approved_maintenance", 5.2 - i * 0.31, "network", "10.10.99.10", f"10.10.20.{10 + i % 4}", "allow", user="administrator", host=hosts[i % len(hosts)], port=[22, 443, 445, 3389][i % 4], protocol="tcp", result="success", change_ticket="CHG-SYNTH-APPROVED-SCAN", approved_activity=True)

    # J: recent multi-stage campaign with consistent actor, identity, and assets (10).
    stages = [
        ("port_scan", "192.0.2.200", "10.10.20.10", "WEB-PORTAL-01", 443, "unattributed"),
        ("failed_login", "192.0.2.200", "10.10.0.20", "VPN-GW-01", 443, "a.sharma"),
        ("credential_abuse", "192.0.2.200", "10.10.10.21", "PAYMENTS-WS01", 443, "a.sharma"),
        ("lateral_movement", "10.10.10.21", "10.10.30.5", "SOC-JUMP01", 445, "a.sharma"),
        ("privilege_escalation", "10.10.30.5", "10.10.30.5", "SOC-JUMP01", 5985, "a.sharma"),
        ("lateral_movement", "10.10.30.5", "10.10.40.11", "DB-PAYMENTS-01", 5432, "a.sharma"),
        ("credential_abuse", "10.10.30.5", "10.10.40.11", "DB-PAYMENTS-01", 5432, "a.sharma"),
        ("beaconing", "10.10.40.11", "203.0.113.200", "DB-PAYMENTS-01", 443, "a.sharma"),
        ("data_exfiltration", "10.10.40.11", "203.0.113.200", "DB-PAYMENTS-01", 443, "a.sharma"),
        ("data_exfiltration", "10.10.40.11", "203.0.113.200", "DB-PAYMENTS-01", 443, "a.sharma"),
    ]
    for i, (action, src, dst, host, port, user) in enumerate(stages):
        add("multi_stage_campaign", 0.035 - i * 0.003, "auth" if action in {"failed_login", "credential_abuse", "privilege_escalation", "lateral_movement"} else "network", src, dst, action, user=user, host=host, port=port, protocol="https" if port == 443 else "tcp", result="failure" if action == "failed_login" else "success", bytes_out=90000000 if action == "data_exfiltration" else 12000)

    if len(events) != EVENT_COUNT:
        raise AssertionError(f"Expected {EVENT_COUNT} events, generated {len(events)}")
    return events


def _write_dataset(events: list[dict[str, Any]]) -> None:
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATASET_PATH.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")


def _tagged_incident_count(events: list[dict[str, Any]]) -> int:
    return sum(1 for event in events if (event.get("raw_event") or {}).get("dataset_tag") == DATASET_TAG)


def _stamp_campaigns(events: list[dict[str, Any]], campaigns: list[dict[str, Any]]) -> None:
    memberships = {
        event_id: campaign
        for campaign in campaigns
        for event_id in campaign.get("incident_ids", [])
    }
    for event in events:
        campaign = memberships.get(event.get("event_id"))
        event["campaign"] = (
            {
                "campaign_id": campaign["campaign_id"],
                "name": campaign["name"],
                "severity": campaign["severity"],
                "incident_count": campaign["incident_count"],
                "furthest_stage": campaign["furthest_stage"],
                "progression_pct": campaign["progression_pct"],
            }
            if campaign
            else None
        )


def seed(*, force: bool = False, regenerate: bool = False) -> dict[str, Any]:
    settings = get_database_settings()
    if not settings.is_postgresql:
        raise RuntimeError("Synthetic seeding requires DB_BACKEND=postgresql.")

    init_db()
    try:
        existing = get_all_incidents()
        tagged_before = _tagged_incident_count(existing)
        if tagged_before and not force:
            return {
                "status": "already_seeded",
                "raw_events": EVENT_COUNT,
                "tagged_incidents": tagged_before,
                "message": "Dataset already exists; use --force for stable-ID reprocessing.",
            }

        if regenerate or not DATASET_PATH.exists():
            _write_dataset(generate_dataset())

        raw_text = DATASET_PATH.read_text(encoding="utf-8")
        raw_events = json.loads(raw_text)
        normalized = process_json_text(raw_text)
        pipeline_result = run_full_pipeline(normalized)
        generated = pipeline_result["events"]

        combined_by_id = {event.get("event_id"): event for event in existing if event.get("event_id")}
        combined_by_id.update({event.get("event_id"): event for event in generated if event.get("event_id")})
        combined = list(combined_by_id.values())
        campaign_result = correlate_campaigns(combined)
        campaigns = campaign_result["campaigns"]
        _stamp_campaigns(combined, campaigns)
        persist_pipeline_results(combined, campaigns)

        return {
            "status": "seeded",
            "raw_events": len(raw_events),
            "events_accepted": len(normalized),
            "incidents_generated": len(generated),
            "campaigns_generated": len(campaigns),
            "pipeline_failures": len(raw_events) - len(generated),
            "timing": pipeline_result.get("timing", {}),
        }
    finally:
        close_db()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Reprocess stable event IDs if already seeded.")
    parser.add_argument("--regenerate", action="store_true", help="Regenerate the local raw dataset file.")
    args = parser.parse_args()
    result = seed(force=args.force, regenerate=args.regenerate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
