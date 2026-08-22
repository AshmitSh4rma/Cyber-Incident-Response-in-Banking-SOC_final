from datetime import UTC, datetime

import pytest

from prototype_ai_chat.intent_router import route_intent


@pytest.mark.parametrize(
    ("question", "intent"),
    [
        ("How many incidents are stored?", "incident_count"),
        ("Show me recent incidents.", "recent_incidents"),
        ("What are the most severe incidents?", "high_severity_incidents"),
        ("Explain incident EVT-123.", "incident_detail"),
        ("What happened from 192.0.2.10?", "source_ip_activity"),
        ("What happened to user alice?", "user_activity"),
        ("Which MITRE techniques are appearing?", "mitre_summary"),
        ("Show T1110.", "mitre_technique"),
        ("What CIS controls are relevant?", "control_summary"),
        ("Show OWASP controls.", "control_framework"),
        ("What are our active campaigns?", "campaign_list"),
        ("Give me a SOC briefing.", "soc_overview"),
        ("Show destination 2001:db8::5", "destination_ip_activity"),
        ("Show host web-01", "asset_activity"),
        ("Show open incidents", "status_filter"),
        ("Show threat type web_attack", "threat_type_filter"),
        ("Show critical CVSS incidents", "cvss_severity"),
        ("What are the highest CVSS incidents?", "highest_cvss"),
        ("Show campaign CMP-001", "campaign_detail"),
        ("Show MITRE tactic Credential Access", "mitre_tactic"),
        ("Show kill-chain stage Discovery", "kill_chain_stage"),
        ("Show control CIS-6.2", "control_lookup"),
        ("What CIS or OWASP controls are showing up?", "control_summary"),
        ("hi", "greeting"),
        ("hello", "greeting"),
        ("what is SOC?", "general_security"),
        ("what is SIEM?", "general_security"),
        ("what is MITRE ATT&CK?", "general_security"),
        ("what is CVSS?", "general_security"),
        ("Explain phishing", "general_security"),
        ("What can you do?", "capabilities"),
        ("Who won the football match?", "out_of_scope"),
        ("What are the MITRE techniques in our incidents?", "mitre_summary"),
        ("hi lol", "greeting"),
        ("hello there", "greeting"),
        ("hi show me critical incidents", "high_severity_incidents"),
        ("give me the overview of anyone log", "sample_incident"),
        ("give me the overview of any one log", "sample_incident"),
        ("show me any log", "sample_incident"),
        ("show me one recent log", "sample_incident"),
        ("explain a log", "sample_incident"),
        ("hello give me any one log", "sample_incident"),
        ("write me a cake recipe", "out_of_scope"),
        ("How should I triage a phishing alert?", "general_security"),
        ("Help me build an incident response playbook", "general_security"),
        ("Compare EDR and XDR for a SOC", "general_security"),
        ("How do false positives affect alert triage?", "general_security"),
        ("Explain containment and eradication", "general_security"),
        ("Show incidents", "recent_incidents"),
        ("List security alerts", "recent_incidents"),
        ("how many total logs we have in the database", "incident_count"),
        ("how many logs are there", "incident_count"),
        ("how many security records are stored", "incident_count"),
        ("total incidents", "incident_count"),
        ("how many SQL injection related logs are with us", "filtered_incident_count"),
        ("how many SQL injection incidents do we have", "filtered_incident_count"),
        ("how many critical incidents are there", "filtered_incident_count"),
        ("how many open incidents are there", "filtered_incident_count"),
        ("how many incidents came from 198.51.100.10", "filtered_incident_count"),
        ("how many incidents involve user a.sharma", "filtered_incident_count"),
        ("how many incidents affected DB-PAYMENTS-01", "filtered_incident_count"),
        ("what is SQL injection", "general_security"),
        ("how many attacks do we have right now?", "incident_count"),
        ("show me recent attacks", "recent_incidents"),
        ("show me critical attacks", "high_severity_incidents"),
        ("show me the worst attack", "highest_risk_incident"),
        ("give me one attack", "sample_incident"),
        ("give me one sql injection incident", "threat_type_filter"),
        ("show me one sql injection attack", "threat_type_filter"),
        ("what is a cyber attack?", "general_security"),
        ("what is a sql injection attack?", "general_security"),
        ("which user is causing the most trouble?", "top_risky_users"),
        ("which user looks most suspicious?", "top_risky_users"),
        ("which ip looks most dangerous?", "top_risky_ips"),
        ("show most dangrous ip", "top_risky_ips"),
        ("give me all attacks on DB-PAYMENTS-01", "asset_activity"),
        ("what happened in last 24 hrs?", "recent_incidents"),
        ("what are the top 5 threats right now?", "top_threat_types"),
        ("are any of these attacks connected?", "campaign_list"),
        ("what happened today?", "recent_incidents"),
        ("why is the worst attack considered critical?", "highest_risk_incident"),
        ("show me the most dangerous campaign", "campaign_list"),
        ("what control should we implement first?", "control_summary"),
    ],
)
def test_required_intents(question, intent):
    assert route_intent(question).intent == intent


def test_entity_extraction_is_explicit_and_normalized():
    assert route_intent("Explain incident EVT-123").filters["event_id"] == "EVT-123"
    assert route_intent("Show campaign CMP-003").filters["campaign_id"] == "CMP-003"
    assert route_intent("Show T1110.001").filters["technique"] == "T1110.001"
    assert route_intent("What happened to account alice@example.com?").filters["user"] == "alice@example.com"


@pytest.mark.parametrize(
    ("phrase", "seconds"),
    [("last hour", 3600), ("past hour", 3600), ("last 24 hours", 86400),
     ("last day", 86400), ("last week", 604800)],
)
def test_relative_time_ranges(phrase, seconds):
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    plan = route_intent(f"Show incidents from the {phrase}", now=now)
    start = datetime.fromisoformat(plan.filters["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(plan.filters["end"].replace("Z", "+00:00"))
    assert plan.intent == "recent_incidents"
    assert (end - start).total_seconds() == seconds


def test_today_starts_at_utc_midnight():
    now = datetime(2026, 8, 22, 12, 30, tzinfo=UTC)
    plan = route_intent("Show incidents today", now=now)
    assert plan.filters["start"] == "2026-08-22T00:00:00Z"
    assert plan.filters["end"] == "2026-08-22T12:30:00Z"


@pytest.mark.parametrize(
    ("question", "intent"),
    [("", "unknown"), ("purple banana telescope", "out_of_scope"),
     ("from 999.999.1.1", "out_of_scope")],
)
def test_unrecognized_questions_do_not_speculate(question, intent):
    plan = route_intent(question)
    assert plan.intent == intent
    assert plan.filters == {}


@pytest.mark.parametrize("question", ["hi", " hi!!! ", "hello sentra", "hey there", "good morning", "good evening"])
def test_greetings_tolerate_harmless_spacing_and_punctuation(question):
    assert route_intent(question).intent == "greeting"


def test_filtered_count_entities_are_normalized():
    assert route_intent("how many SQL injection logs do we have").filters == {"threat_type": "web_attack"}
    assert route_intent("how many critical incidents are there").filters == {"severity": "critical"}
    assert route_intent("how many open incidents are there").filters == {"status": "open"}
    assert route_intent("how many incidents came from 198.51.100.10").filters == {"source_ip": "198.51.100.10"}
    assert route_intent("how many incidents involve user a.sharma").filters == {"user": "a.sharma"}
    assert route_intent("how many incidents affected DB-PAYMENTS-01").filters == {"asset": "DB-PAYMENTS-01"}


def test_attack_sample_and_risk_plans_are_bounded_and_deterministic():
    assert route_intent("show me the worst attack").limit == 1
    plan = route_intent("give me one SQL injection incident")
    assert plan.limit == 1
    assert plan.filters == {"threat_type": "web_attack"}


def test_aggregate_limits_and_asset_entity_are_normalized():
    assert route_intent("what are the top 5 threats right now?").limit == 5
    assert route_intent("give me the top 99 attacks").limit == 20
    assert route_intent("give me all attacks on DB-PAYMENTS-01").filters == {"asset": "DB-PAYMENTS-01"}


@pytest.mark.parametrize("phrase", ["last 24 hrs", "last 24hr", "last 24hrs", "last 24 h", "past 24 hrs"])
def test_common_24_hour_aliases(phrase):
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    plan = route_intent(f"what happened in {phrase}?", now=now)
    start = datetime.fromisoformat(plan.filters["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(plan.filters["end"].replace("Z", "+00:00"))
    assert plan.intent == "recent_incidents"
    assert (end - start).total_seconds() == 86400


@pytest.mark.parametrize("phrase", ["last 1 hr", "past hr"])
def test_common_one_hour_aliases(phrase):
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    plan = route_intent(f"what happened {phrase}?", now=now)
    start = datetime.fromisoformat(plan.filters["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(plan.filters["end"].replace("Z", "+00:00"))
    assert (end - start).total_seconds() == 3600


def test_yesterday_is_previous_utc_calendar_day():
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    plan = route_intent("what happened yesterday?", now=now)
    assert plan.filters == {"start": "2026-08-21T00:00:00Z", "end": "2026-08-22T00:00:00Z"}
