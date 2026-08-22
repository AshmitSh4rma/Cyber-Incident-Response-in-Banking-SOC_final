"""
Tests for ATT&CK mapping and campaign correlation.

The correlation tests are mostly about what must NOT be grouped. Over-correlation
is the failure mode that makes this feature useless: one mega-campaign containing
everything tells an analyst nothing, and it is easy to produce by accident.
"""

import pytest

from layer_2_detection.campaign_correlator import correlate_campaigns
from layer_2_detection.mitre_mapper import TACTICS, map_attack

# ─────────────────────────────────────────────────────────────────────────────
# ATT&CK mapping
# ─────────────────────────────────────────────────────────────────────────────

def test_tactic_set_is_complete_and_ordered():
    assert len(TACTICS) == 15
    orders = [t["order"] for t in TACTICS]
    assert orders == sorted(orders)
    assert orders == list(range(1, 16))
    ids = [t["id"] for t in TACTICS]
    assert len(set(ids)) == 15
    # Spot-check the current matrix, including the renamed/added tactics.
    assert {"id": "TA0043", "name": "Reconnaissance", "order": 1} in TACTICS
    assert any(t["id"] == "TA0112" and t["name"] == "Defense Impairment" for t in TACTICS)
    assert any(t["id"] == "TA0005" and t["name"] == "Stealth" for t in TACTICS)


@pytest.mark.parametrize(
    "threat_type,expected_technique",
    [
        ("port_scan", "T1595.001"),
        ("brute_force_attempt", "T1110.001"),
        ("lateral_movement", "T1021"),
        ("beaconing", "T1071.001"),
        ("data_exfiltration", "T1041"),
        ("web_attack", "T1190"),
    ],
)
def test_known_threats_map_to_expected_technique(threat_type, expected_technique):
    result = map_attack(threat_type)
    assert result["primary"]["technique_id"] == expected_technique


def test_technique_urls_are_well_formed():
    """Sub-technique ids use a nested path on attack.mitre.org, not a dotted one."""
    result = map_attack("port_scan")
    url = result["primary"]["url"]
    assert url == "https://attack.mitre.org/techniques/T1595/001/"
    assert "." not in url.rsplit("/techniques/", 1)[1]


def test_sql_injection_payload_sharpens_the_technique():
    generic = map_attack("web_attack")
    webshell = map_attack("web_attack", url="/admin/upload.php")
    assert generic["primary"]["technique_id"] == "T1190"
    assert webshell["primary"]["technique_id"] == "T1505.003"
    assert webshell["kill_chain_stage"] == "Persistence"


def test_kill_chain_stage_follows_the_primary_technique_not_the_furthest():
    """
    A port scan cites Active Scanning (Reconnaissance) and Network Service
    Discovery (Discovery). Taking the furthest tactic would rank a scan later in
    the lifecycle than a working exploit, which is backwards.
    """
    scan = map_attack("port_scan")
    exploit = map_attack("web_attack")
    assert scan["kill_chain_stage"] == "Reconnaissance"
    assert scan["kill_chain_order"] < exploit["kill_chain_order"]


def test_unknown_threat_maps_to_nothing_rather_than_guessing():
    result = map_attack("no_such_threat")
    assert result["primary"] is None
    assert result["techniques"] == []
    assert result["kill_chain_stage"] == "unmapped"
    assert result["kill_chain_order"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Campaign correlation
# ─────────────────────────────────────────────────────────────────────────────

def _incident(event_id, ts, src, host, threat, stage_order, stage, label="malicious",
              dest="", user="", severity="high"):
    return {
        "event_id": event_id,
        "raw_event": {"timestamp": ts, "source_ip": src, "affected_host": host,
                      "destination_ip": dest, "affected_user": user},
        "dashboard": {"source_ip": src, "affected_host": host, "destination_ip": dest,
                      "affected_user": user},
        "detection": {"threat_type": threat, "severity": severity, "confidence": 0.9,
                      "label": label},
        "mitre_attack": {
            "kill_chain_stage": stage,
            "kill_chain_order": stage_order,
            "primary": {"technique_id": "T9999", "technique_name": "Test"},
        },
    }


def test_compromise_chain_links_victim_to_next_attacker():
    """The hop that naive source-IP correlation misses."""
    events = [
        _incident("e1", "2026-01-01T01:00:00Z", "203.0.113.9", "web-01", "web_attack", 3, "Initial Access"),
        _incident("e2", "2026-01-01T02:00:00Z", "web-01", "db-01", "lateral_movement", 11, "Lateral Movement"),
    ]
    result = correlate_campaigns(events)
    assert len(result["campaigns"]) == 1
    campaign = result["campaigns"][0]
    assert campaign["incident_count"] == 2
    assert campaign["furthest_stage"] == "Lateral Movement"
    assert any("became the source" in reason for reason in campaign["linked_by"])


def test_recon_only_does_not_claim_a_host_was_compromised():
    """
    A scan reaching a host does not make that host the attacker's. Without this
    gate, a scheduled vulnerability scan chains onto everything its targets
    later did — which pulls an authorised scan into a real breach.
    """
    events = [
        # Scanner touches core-app. Reconnaissance only.
        _incident("scan", "2026-01-01T00:00:00Z", "10.99.0.5", "core-app", "port_scan",
                  1, "Reconnaissance", severity="medium"),
        # core-app later originates activity for unrelated reasons.
        _incident("later", "2026-01-01T05:00:00Z", "core-app", "db-01", "lateral_movement",
                  11, "Lateral Movement"),
    ]
    result = correlate_campaigns(events)
    assert result["campaigns"] == [], "recon must not be treated as a compromise"


def test_shared_asset_alone_does_not_group():
    """Every alert in a real network touches some shared server."""
    events = [
        _incident("a", "2026-01-01T01:00:00Z", "1.1.1.1", "shared-host", "web_attack", 3, "Initial Access"),
        _incident("b", "2026-01-01T02:00:00Z", "2.2.2.2", "shared-host", "web_attack", 3, "Initial Access"),
    ]
    result = correlate_campaigns(events)
    assert result["campaigns"] == []


def test_same_source_groups():
    events = [
        _incident("a", "2026-01-01T01:00:00Z", "45.1.2.3", "h1", "brute_force_attempt", 9, "Credential Access"),
        _incident("b", "2026-01-01T01:05:00Z", "45.1.2.3", "h1", "brute_force_attempt", 9, "Credential Access"),
    ]
    result = correlate_campaigns(events)
    assert len(result["campaigns"]) == 1
    assert result["campaigns"][0]["incident_count"] == 2


def test_benign_and_suppressed_events_are_excluded():
    events = [
        _incident("a", "2026-01-01T01:00:00Z", "45.1.2.3", "h1", "brute_force_attempt", 9, "Credential Access"),
        _incident("b", "2026-01-01T01:05:00Z", "45.1.2.3", "h1", "brute_force_attempt", 9, "Credential Access"),
        _incident("benign", "2026-01-01T01:06:00Z", "45.1.2.3", "h1", "unknown", 0, "unmapped", label="benign"),
    ]
    suppressed = _incident("sup", "2026-01-01T01:07:00Z", "45.1.2.3", "h1", "brute_force_attempt", 9, "Credential Access")
    suppressed["detection"]["suppressed"] = True
    events.append(suppressed)

    result = correlate_campaigns(events)
    assert len(result["campaigns"]) == 1
    members = result["campaigns"][0]["incident_ids"]
    assert set(members) == {"a", "b"}


def test_singletons_are_not_called_campaigns():
    events = [_incident("only", "2026-01-01T01:00:00Z", "9.9.9.9", "h1", "web_attack", 3, "Initial Access")]
    result = correlate_campaigns(events)
    assert result["campaigns"] == []
    assert result["standalone_incident_ids"] == ["only"]


def test_long_chain_escalates_severity():
    """Three stages by one actor is worse than any single alert in it."""
    events = [
        _incident("a", "2026-01-01T01:00:00Z", "203.0.113.9", "web-01", "web_attack", 3,
                  "Initial Access", severity="medium"),
        _incident("b", "2026-01-01T02:00:00Z", "web-01", "app-01", "lateral_movement", 11,
                  "Lateral Movement", severity="medium"),
        _incident("c", "2026-01-01T03:00:00Z", "app-01", "db-01", "data_exfiltration", 14,
                  "Exfiltration", severity="medium"),
    ]
    result = correlate_campaigns(events)
    campaign = result["campaigns"][0]
    assert campaign["member_max_severity"] == "medium"
    assert campaign["escalated"] is True
    assert campaign["severity"] == "high"
    assert campaign["stages_reached"] == 3


def test_progression_and_narrative_reflect_the_chain():
    events = [
        _incident("a", "2026-01-01T01:00:00Z", "203.0.113.9", "web-01", "web_attack", 3, "Initial Access"),
        _incident("b", "2026-01-01T02:00:00Z", "web-01", "db-01", "data_exfiltration", 14, "Exfiltration"),
    ]
    campaign = correlate_campaigns(events)["campaigns"][0]
    assert campaign["progression_pct"] == round(100 * 14 / 15)
    assert "Exfiltration" in campaign["narrative"]
    # The external address is the origin, not the internal hop.
    assert "203.0.113.9" in campaign["narrative"]


def test_correlation_is_deterministic():
    events = [
        _incident("a", "2026-01-01T01:00:00Z", "203.0.113.9", "web-01", "web_attack", 3, "Initial Access"),
        _incident("b", "2026-01-01T02:00:00Z", "web-01", "db-01", "lateral_movement", 11, "Lateral Movement"),
    ]
    first = correlate_campaigns(events)
    second = correlate_campaigns(events)
    assert first == second
