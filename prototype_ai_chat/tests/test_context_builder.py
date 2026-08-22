import json

import pytest

from prototype_ai_chat import context_builder as builder
from prototype_ai_chat import retrieval
from prototype_ai_chat.intent_router import RetrievalPlan


def incident(event_id="EVT-1", narrative="short"):
    return retrieval.IncidentRecord(
        event_id, "2026-08-22T01:00:00Z", "high", "open", "web_attack",
        "192.0.2.1", "alice", "web-01",
        {"raw_event": {"destination_ip": "198.51.100.2"},
         "ai_analysis": {"narrative": narrative},
         "mitre_attack": {"techniques": [{"technique_id": "T1110", "technique_name": "Brute Force"}]},
         "cvss": {"base_score": 8.2, "severity": "high"},
         "cis": {"framework": "CIS", "benchmark_id": "CIS-6.2", "title": "Access Control",
                 "remediation": narrative}}, True,
    )


def campaign(campaign_id="CMP-1"):
    return retrieval.CampaignRecord(
        campaign_id, "critical", 90, "2026-08-22T00:00:00Z", "2026-08-22T01:00:00Z",
        {"name": "Campaign", "narrative": "Stored campaign narrative", "incident_ids": ["EVT-1"]}, True,
    )


def empty_mitre():
    return retrieval.MITRESummary(1, 1, False, (), (retrieval.MITRETechniqueCount("T1110", "Brute Force", 1),), ())


def empty_controls():
    return retrieval.ControlSummary(1, 1, False, (), (retrieval.ControlCount("CIS", "CIS-6.2", "Access Control", 1),))


@pytest.mark.parametrize(
    ("plan", "patched", "section"),
    [
        (RetrievalPlan("recent_incidents"), "get_recent_incidents", "incidents"),
        (RetrievalPlan("high_severity_incidents"), "get_high_severity_incidents", "incidents"),
        (RetrievalPlan("incident_detail", {"event_id": "EVT-1"}), "get_incident_by_id", "incidents"),
        (RetrievalPlan("source_ip_activity", {"source_ip": "192.0.2.1"}), "search_incidents", "incidents"),
        (RetrievalPlan("user_activity", {"user": "alice"}), "search_incidents", "incidents"),
        (RetrievalPlan("campaign_list"), "list_campaigns", "campaigns"),
        (RetrievalPlan("campaign_detail", {"campaign_id": "CMP-1"}), "get_campaign_by_id", "campaigns"),
    ],
)
def test_major_incident_and_campaign_dispatch(monkeypatch, plan, patched, section):
    value = campaign() if section == "campaigns" else incident()
    monkeypatch.setattr(retrieval, patched, lambda *args, **kwargs: value if plan.intent.endswith("detail") else [value])
    context = builder.build_context(plan, "query")
    assert context[section][0]["campaign_id" if section == "campaigns" else "event_id"]


def test_count_cvss_mitre_and_control_dispatch(monkeypatch):
    monkeypatch.setattr(retrieval, "count_incidents", lambda: 25)
    assert builder.build_context(RetrievalPlan("incident_count"), "q")["summary"]["incident_count"] == 25
    cvss = retrieval.CVSSRecord("EVT-1", "2026-08-22T01:00:00Z", "high", "web", 9.8, "critical", "AV:N")
    monkeypatch.setattr(retrieval, "get_highest_cvss_incidents", lambda limit: [cvss])
    assert builder.build_context(RetrievalPlan("highest_cvss"), "q")["cvss"][0]["event_id"] == "EVT-1"
    monkeypatch.setattr(retrieval, "get_mitre_summary", empty_mitre)
    assert builder.build_context(RetrievalPlan("mitre_summary"), "q")["mitre"]["techniques"][0]["technique_id"] == "T1110"
    monkeypatch.setattr(retrieval, "get_control_summary", empty_controls)
    assert builder.build_context(RetrievalPlan("control_summary"), "q")["controls"]["controls"][0]["control_id"] == "CIS-6.2"


def test_sample_incident_uses_one_recent_normalized_record(monkeypatch):
    calls = []
    monkeypatch.setattr(retrieval, "get_recent_incidents", lambda limit: calls.append(limit) or [incident("EVT-SAMPLE")])
    context = builder.build_context(RetrievalPlan("sample_incident", limit=1), "show one log")
    assert calls == [1]
    assert context["incidents"][0]["event_id"] == "EVT-SAMPLE"
    assert "log_family" not in context["incidents"][0]
    assert context["evidence"] == [{"type": "incident", "id": "EVT-SAMPLE"}]
    assert '"payload"' not in json.dumps(context)


def test_highest_risk_incident_returns_exactly_one_grounded_record(monkeypatch):
    monkeypatch.setattr(retrieval, "get_highest_risk_incident", lambda: incident("EVT-RISK"))
    context = builder.build_context(RetrievalPlan("highest_risk_incident", limit=1), "worst attack")
    assert [item["event_id"] for item in context["incidents"]] == ["EVT-RISK"]
    assert context["evidence"] == [{"type": "incident", "id": "EVT-RISK"}]


@pytest.mark.parametrize(
    ("intent", "function", "section", "kind"),
    [
        ("top_risky_users", "get_top_risky_users", "users", "user"),
        ("top_risky_ips", "get_top_risky_source_ips", "source_ips", "source_ip"),
        ("top_threat_types", "get_top_threat_types", "threat_types", "threat_type"),
    ],
)
def test_risk_aggregate_context_is_bounded_and_grounded(monkeypatch, intent, function, section, kind):
    values = [retrieval.RiskAggregate("value-1", 7, 2, 3, 9.4, "2026-08-22T01:00:00Z")]
    monkeypatch.setattr(retrieval, function, lambda limit: values)
    context = builder.build_context(RetrievalPlan(intent, limit=5), "rank")
    assert context["rankings"][section][0]["critical_count"] == 2
    assert context["evidence"] == [{"type": kind, "id": "value-1"}]


def test_campaign_relationship_context_uses_persisted_membership(monkeypatch):
    value = campaign("CMP-related")
    relationship = retrieval.CampaignRelationship(value, ("EVT-1", "EVT-2"))
    monkeypatch.setattr(retrieval, "get_campaign_relationships", lambda ids, minimum_matches=2: [relationship])
    plan = RetrievalPlan("campaign_relationship", {"incident_ids": ["EVT-1", "EVT-2"]})
    context = builder.build_context(plan, "are these connected")
    assert context["relationships"] == [{"campaign_id": "CMP-related", "matching_incident_ids": ["EVT-1", "EVT-2"]}]
    assert {item["id"] for item in context["evidence"]} == {"CMP-related"}


def test_filtered_count_dispatches_without_display_limit(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        retrieval, "count_incidents_filtered",
        lambda **kwargs: captured.update(kwargs) or 37,
    )
    plan = RetrievalPlan("filtered_incident_count", {"threat_type": "web_attack"}, limit=0)
    context = builder.build_context(plan, "how many")
    assert context["summary"] == {"incident_count": 37, "filters": {"threat_type": "web_attack"}}
    assert captured == {"threat_type": "web_attack"}


def test_context_bounds_text_evidence_and_has_no_payload(monkeypatch):
    oversized = [incident(f"EVT-{index}", "x" * 2000) for index in range(30)]
    monkeypatch.setattr(retrieval, "get_recent_incidents", lambda limit: oversized)
    context = builder.build_context(RetrievalPlan("recent_incidents", limit=100), "q")
    assert len(context["incidents"]) == builder.MAX_CONTEXT_INCIDENTS
    assert len(context["evidence"]) <= builder.MAX_EVIDENCE_ITEMS
    assert len(context["incidents"][0]["analysis"]) == builder.MAX_TEXT_LENGTH
    assert context["metadata"]["truncated"] is True
    serialized = json.dumps(context)
    assert '"payload"' not in serialized


def test_campaign_and_evidence_caps(monkeypatch):
    monkeypatch.setattr(retrieval, "list_campaigns", lambda limit: [campaign(f"CMP-{i}") for i in range(15)])
    context = builder.build_context(RetrievalPlan("campaign_list", limit=100), "q")
    assert len(context["campaigns"]) == builder.MAX_CONTEXT_CAMPAIGNS
    assert all(item["campaign_id"] for item in context["campaigns"])
    assert context["metadata"]["truncated"] is True


def test_soc_overview_is_compact_and_grounded(monkeypatch):
    monkeypatch.setattr(retrieval, "count_incidents", lambda: 25)
    monkeypatch.setattr(retrieval, "get_recent_incidents", lambda limit: [incident("EVT-1")])
    monkeypatch.setattr(retrieval, "get_high_severity_incidents", lambda limit: [incident("EVT-2")])
    monkeypatch.setattr(retrieval, "list_campaigns", lambda limit: [campaign()])
    monkeypatch.setattr(retrieval, "get_highest_cvss_incidents", lambda limit: [])
    monkeypatch.setattr(retrieval, "get_mitre_summary", empty_mitre)
    monkeypatch.setattr(retrieval, "get_control_summary", empty_controls)
    context = builder.build_context(RetrievalPlan("soc_overview"), "brief me")
    assert context["summary"]["incident_count"] == 25
    assert {item["id"] for item in context["evidence"]} >= {"EVT-1", "EVT-2", "CMP-1", "T1110", "CIS-6.2"}
    json.dumps(context)


def test_unknown_context_executes_no_retrieval(monkeypatch):
    monkeypatch.setattr(retrieval, "count_incidents", lambda: pytest.fail("retrieval called"))
    context = builder.build_context(RetrievalPlan("unknown", confidence=0.0), "nonsense")
    assert context["evidence"] == []
    assert context["metadata"]["records_considered"] == 0
