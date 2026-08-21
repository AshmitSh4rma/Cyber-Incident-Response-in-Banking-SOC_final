"""
Tests for the human-in-the-loop response gate, value metrics, and audit reports.
"""

from audit_report import campaign_report, incident_report
from layer_6_response.response_orchestrator import run_response
from soc_metrics import compute_metrics


def _event(threat="web_attack", severity="high", host="dmz-web-01", user="svc_payments"):
    return {
        "event_id": "evt-test",
        "raw_event": {"timestamp": "2026-08-22T02:21:44Z", "source_ip": "203.0.113.55",
                      "affected_host": host, "affected_user": user},
        "dashboard": {"source_ip": "203.0.113.55", "affected_host": host,
                      "affected_user": user, "destination_ip": "10.20.0.11"},
        "detection": {"threat_type": threat, "severity": severity, "confidence": 0.92,
                      "label": "malicious", "reasoning": ["signature matched"],
                      "triggered_engines": ["threat_analysis"]},
        "cvss": {"base_score": 8.2, "severity": severity,
                 "vector_string": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"},
        "ai_analysis": {"intent": "Web Application Attack", "narrative": "A payload was sent.",
                        "impact": {"confidentiality": "high", "integrity": "low", "availability": "none"}},
        "cis": {"benchmark_id": "OWASP-A04", "title": "Insecure Design", "framework": "OWASP",
                "description": "Design flaws.", "remediation": "Use secure patterns.",
                "match_type": "catalog_retrieval"},
        "mitre_attack": {
            "kill_chain_stage": "Initial Access",
            "kill_chain_order": 3,
            "primary": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                        "tactic_id": "TA0001", "tactic_name": "Initial Access",
                        "url": "https://attack.mitre.org/techniques/T1190/"},
            "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                            "tactic_name": "Initial Access", "url": "x"}],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Human-in-the-loop gating
# ─────────────────────────────────────────────────────────────────────────────

def test_blocking_an_attacker_ip_auto_executes():
    """
    The narrowest, most reversible action in the playbook. A substring match on
    "lock" once gated this, because "Block" contains "lock".
    """
    result = run_response(_event(threat="brute_force_attempt", host="ssh-bastion-01"))
    blocking = [s for s in result["containment_plan"] if s["action"].lower().startswith("block")]
    assert blocking, "expected a blocking step in the brute-force playbook"
    assert all(s["execution"] == "auto" for s in blocking)


def test_isolating_a_core_banking_host_requires_approval():
    result = run_response(_event(threat="lateral_movement", host="db-core-01", severity="critical"))
    isolating = [s for s in result["containment_plan"] if "isolate" in s["action"].lower()]
    assert isolating
    assert all(s["execution"] == "requires_approval" for s in isolating)
    assert all(s["blast_radius"] == "service-affecting" for s in isolating)
    assert result["requires_human_approval"] is True


def test_gate_is_on_blast_radius_not_severity():
    """A critical verdict does not earn the right to break production."""
    critical_but_contained = run_response(_event(threat="web_attack", host="dmz-web-01", severity="critical"))
    auto = [s for s in critical_but_contained["containment_plan"] if s["execution"] == "auto"]
    assert auto, "a critical incident can still have safely automatable containment"


def test_every_containment_step_is_classified():
    result = run_response(_event(threat="data_exfiltration", host="db-core-01"))
    assert len(result["containment_plan"]) == len(result["containment_steps"])
    for step in result["containment_plan"]:
        assert step["execution"] in {"auto", "requires_approval"}
        assert step["blast_radius"] in {"contained", "host-affecting", "service-affecting"}
        assert step["rationale"]


def test_counts_add_up():
    result = run_response(_event(threat="lateral_movement", host="core-app-02"))
    assert result["auto_executable"] + result["awaiting_approval"] == len(result["containment_plan"])


def test_suppressed_incident_asks_for_no_action():
    event = _event()
    event["detection"]["suppressed"] = True
    event["detection"]["reasoning"] = ["[SUPPRESSED] known good"]
    result = run_response(event)
    assert result["playbook"] == "suppressed"
    assert result["containment_steps"] == []
    assert result["priority"] == "P3"


# ─────────────────────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────────────────────

def _stored(label, severity="high", suppressed=False, auto=2, gated=1):
    return {
        "event_id": f"e-{label}-{severity}-{suppressed}-{auto}",
        "detection": {"label": label, "severity": severity, "suppressed": suppressed},
        "cis": {"benchmark_id": "CIS-1.1"},
        "cvss": {"base_score": 7.0},
        "mitre_attack": {"primary": {"technique_id": "T1190"}},
        "response": {"auto_executable": auto, "awaiting_approval": gated,
                     "requires_human_approval": gated > 0},
    }


def test_benign_and_suppressed_are_excluded_from_actionable():
    incidents = [
        _stored("malicious"), _stored("suspicious"),
        _stored("benign", severity="low"),
        _stored("suspicious", suppressed=True),
    ]
    metrics = compute_metrics(incidents, [], [])
    assert metrics["queue"]["total_alerts"] == 4
    assert metrics["queue"]["benign_filtered"] == 1
    assert metrics["queue"]["analyst_suppressed"] == 1
    assert metrics["queue"]["actionable"] == 2


def test_consolidation_counts_campaigns_plus_standalone():
    incidents = [_stored("malicious") for _ in range(9)]
    for i, inc in enumerate(incidents):
        inc["event_id"] = f"e{i}"
    campaigns = [{"campaign_id": "CMP-001", "incident_count": 7}]
    metrics = compute_metrics(incidents, campaigns, [])
    # 9 actionable, 7 in one campaign, 2 standalone -> 3 investigations
    assert metrics["consolidation"]["investigations"] == 3
    assert metrics["consolidation"]["ratio"] == 3.0


def test_time_model_states_its_assumptions():
    metrics = compute_metrics([_stored("malicious")], [], [])
    assumptions = metrics["time"]["assumptions"]
    assert assumptions["manual_triage_minutes_per_alert"] > 0
    assert assumptions["review_minutes_per_incident"] > 0
    assert "assumption" in assumptions["note"].lower()


def test_saving_is_never_negative():
    """More investigations than alerts must not produce a negative saving."""
    metrics = compute_metrics([_stored("malicious")], [{"campaign_id": "c", "incident_count": 50}], [])
    assert metrics["time"]["minutes_saved"] >= 0


def test_empty_state_does_not_divide_by_zero():
    metrics = compute_metrics([], [], [])
    assert metrics["queue"]["total_alerts"] == 0
    assert metrics["coverage"]["cis_mapped_pct"] == 0
    assert metrics["consolidation"]["investigations"] == 0
    assert metrics["worst_campaign"] is None


def test_auto_share_reflects_the_gate():
    incidents = [_stored("malicious", auto=3, gated=1)]
    metrics = compute_metrics(incidents, [], [])
    assert metrics["response"]["auto_executable_actions"] == 3
    assert metrics["response"]["gated_actions"] == 1
    assert metrics["response"]["auto_share_pct"] == 75


# ─────────────────────────────────────────────────────────────────────────────
# Audit reports
# ─────────────────────────────────────────────────────────────────────────────

def test_incident_report_contains_the_audit_evidence():
    event = _event()
    event["response"] = run_response(event)
    report = incident_report(event)

    for required in ("# Incident Record", "OWASP-A04", "T1190", "Control Mapping (Audit Evidence)",
                     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "Containment plan"):
        assert required in report, f"report missing {required!r}"


def test_incident_report_does_not_invent_sections():
    """A thin incident should produce a short report, not one padded with TBDs."""
    thin = {"event_id": "evt-thin", "detection": {"label": "suspicious", "severity": "low"}}
    report = incident_report(thin)
    assert "TBD" not in report
    assert "None recorded" in report or "No control mapping" in report
    assert report.startswith("# Incident Record")


def test_campaign_report_renders_the_chain_in_lifecycle_order():
    campaign = {
        "campaign_id": "CMP-001",
        "name": "Data theft originating from 203.0.113.55",
        "severity": "critical",
        "incident_count": 2,
        "incident_ids": ["evt-test"],
        "furthest_stage": "Exfiltration",
        "progression_pct": 93,
        "first_seen": "2026-08-22T02:14:03Z",
        "last_seen": "2026-08-22T03:48:29Z",
        "stages_reached": 2,
        "narrative": "Two alerts describe one sequence.",
        "linked_by": ["same source address 203.0.113.55"],
        "actors": ["203.0.113.55"],
        "assets": ["dmz-web-01"],
        "accounts": ["svc_payments"],
        "techniques": ["T1190", "T1041"],
        "kill_chain": [
            {"stage": "Initial Access", "order": 3, "first_seen": "2026-08-22T02:21:44Z",
             "technique": "T1190", "technique_name": "Exploit Public-Facing Application",
             "event_id": "evt-test"},
            {"stage": "Exfiltration", "order": 14, "first_seen": "2026-08-22T03:48:29Z",
             "technique": "T1041", "technique_name": "Exfiltration Over C2 Channel",
             "event_id": "evt-other"},
        ],
    }
    report = campaign_report(campaign, [_event()])
    assert "# Campaign Report — CMP-001" in report
    assert "Attack Chain" in report
    assert "T1041" in report
    assert "Correlation Basis" in report

    # Order must be checked inside the Attack Chain section. "Exfiltration" also
    # appears earlier in the summary table as the furthest stage reached, so a
    # whole-document index comparison tests nothing.
    chain_section = report.split("## Attack Chain", 1)[1].split("## Correlation Basis", 1)[0]
    assert chain_section.index("Initial Access") < chain_section.index("Exfiltration")
