"""Build bounded, JSON-safe security evidence from deterministic retrieval plans."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from prototype_ai_chat import retrieval
from prototype_ai_chat.claim_verifier import build_canonical_facts
from prototype_ai_chat.intent_router import RetrievalPlan

MAX_CONTEXT_INCIDENTS = 20
MAX_CONTEXT_CAMPAIGNS = 10
MAX_EVIDENCE_ITEMS = 25
MAX_TEXT_LENGTH = 600


def _compact(value: Any) -> Any:
    """Recursively omit absent values while preserving meaningful false/zero values."""
    if isinstance(value, dict):
        return {key: compacted for key, item in value.items()
                if (compacted := _compact(item)) not in (None, "", [], {})}
    if isinstance(value, (list, tuple)):
        return [compacted for item in value if (compacted := _compact(item)) not in (None, "", [], {})]
    return value


def _text(value: Any, state: dict[str, bool]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    clean = value.strip()
    if len(clean) > MAX_TEXT_LENGTH:
        state["truncated"] = True
        return clean[: MAX_TEXT_LENGTH - 1] + "…"
    return clean


def _first(payload: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> Any | None:
    for path in paths:
        value = retrieval.nested_payload_value(payload, *path)
        if value is not None:
            return value
    return None


def _incident(item: retrieval.IncidentRecord, state: dict[str, bool]) -> dict[str, Any]:
    mitre = retrieval._mitre_incident(item)
    cvss = retrieval._cvss_record(item)
    controls = retrieval._incident_controls(item)
    payload = item.payload
    return _compact({
        "event_id": item.event_id,
        "timestamp": item.timestamp,
        "severity": item.severity,
        "status": item.status,
        "threat_type": item.threat_type,
        "source_ip": item.source_ip,
        "destination_ip": retrieval._payload_ip(item, "destination_ip"),
        "affected_user": item.affected_user,
        "affected_host": item.affected_host,
        "log_family": _first(payload, (("raw_event", "log_type"), ("ingestion", "log_family"),
                                        ("feature_engineering", "log_family"))),
        "event_action": _first(payload, (("raw_event", "action"), ("ingestion", "action"))),
        "confidence": _first(payload, (("detection", "confidence"), ("dashboard", "confidence"))),
        "verdict": _first(payload, (("detection", "verdict"), ("detection", "label"))),
        "mitre": None if not mitre else {
            "tactics": list(mitre.tactics),
            "techniques": [asdict(value) for value in retrieval._incident_techniques(mitre)],
            "primary_technique": None if not mitre.primary_technique else asdict(mitre.primary_technique),
            "kill_chain_stage": mitre.kill_chain_stage,
        },
        "cvss": None if not cvss else {
            "score": cvss.cvss_score,
            "severity": cvss.cvss_severity,
            "vector": cvss.cvss_vector,
        },
        "controls": [
            {"framework": value.framework, "control_id": value.control_id, "title": value.title,
             "rationale": _text(value.rationale, state), "remediation": _text(value.remediation, state)}
            for value in controls
        ],
        "analysis": _text(_first(payload, (("ai_analysis", "narrative"), ("ai_analysis", "summary"), ("ai", "narrative"))), state),
        "response_recommendation": _text(
            _first(payload, (("response", "recommendation"), ("response", "recommended_action"),
                             ("final_report", "response_recommendation"))), state
        ),
    })


def _campaign(item: retrieval.CampaignRecord, state: dict[str, bool]) -> dict[str, Any]:
    payload = item.payload
    members = _first(payload, (("incident_ids",), ("member_incident_ids",), ("members",)))
    if not isinstance(members, list):
        members = []
    if len(members) > MAX_EVIDENCE_ITEMS:
        state["truncated"] = True
    member_ids = []
    for value in members[:MAX_EVIDENCE_ITEMS]:
        if isinstance(value, str):
            member_ids.append(value)
        elif isinstance(value, dict):
            identifier = value.get("event_id") or value.get("incident_id")
            if identifier:
                member_ids.append(str(identifier))
    return {
        "campaign_id": item.campaign_id,
        "severity": item.severity,
        "progression_pct": item.progression_pct,
        "first_seen": item.first_seen,
        "last_seen": item.last_seen,
        "name": _text(payload.get("name"), state),
        "narrative": _text(payload.get("narrative"), state),
        "incident_ids": member_ids,
    }


def _json_value(value: Any) -> Any:
    return asdict(value) if is_dataclass(value) else value


def build_context(plan: RetrievalPlan, query: str) -> dict[str, Any]:
    """Execute an allowlisted retrieval plan and return compact grounded context."""
    state = {"truncated": False}
    context: dict[str, Any] = {"intent": plan.intent, "query": query}
    incidents: list[retrieval.IncidentRecord] = []
    campaigns: list[retrieval.CampaignRecord] = []
    aggregate_records_considered = 0
    filters = plan.filters
    requested = min(max(int(plan.limit), 1), MAX_CONTEXT_INCIDENTS)

    if plan.intent == "incident_count":
        context["summary"] = {"incident_count": retrieval.count_incidents()}
    elif plan.intent == "filtered_incident_count":
        allowed = {key: filters[key] for key in (
            "severity", "status", "source_ip", "user", "asset", "threat_type"
        ) if key in filters}
        context["summary"] = {
            "incident_count": retrieval.count_incidents_filtered(**allowed),
            "filters": allowed,
        }
    elif plan.intent == "recent_incidents":
        incidents = (retrieval.search_incidents_by_time(filters.get("start"), filters.get("end"), requested)
                     if filters else retrieval.get_recent_incidents(requested))
    elif plan.intent == "sample_incident":
        incidents = retrieval.get_recent_incidents(1)
    elif plan.intent == "highest_risk_incident":
        value = retrieval.get_highest_risk_incident()
        incidents = [value] if value else []
    elif plan.intent == "top_risky_users":
        values = retrieval.get_top_risky_users(min(plan.limit, 20))
        context["rankings"] = {"users": [_json_value(value) for value in values]}
        aggregate_records_considered = sum(value.total_incidents for value in values)
    elif plan.intent == "top_risky_ips":
        values = retrieval.get_top_risky_source_ips(min(plan.limit, 20))
        context["rankings"] = {"source_ips": [_json_value(value) for value in values]}
        aggregate_records_considered = sum(value.total_incidents for value in values)
    elif plan.intent == "top_threat_types":
        values = retrieval.get_top_threat_types(min(plan.limit, 20))
        context["rankings"] = {"threat_types": [_json_value(value) for value in values]}
        aggregate_records_considered = sum(value.total_incidents for value in values)
    elif plan.intent == "high_severity_incidents":
        incidents = retrieval.get_high_severity_incidents(requested)
    elif plan.intent == "incident_detail":
        value = retrieval.get_incident_by_id(filters["event_id"])
        incidents = [value] if value else []
    elif plan.intent in {"source_ip_activity", "user_activity", "asset_activity", "status_filter", "threat_type_filter"}:
        kwargs = {key: filters[key] for key in ("start", "end", "source_ip", "user", "asset", "status", "threat_type") if key in filters}
        incidents = retrieval.search_incidents(**kwargs, limit=requested)
    elif plan.intent == "destination_ip_activity":
        incidents = retrieval.search_incidents_by_destination_ip(filters["destination_ip"], requested)
    elif plan.intent == "campaign_list":
        campaigns = retrieval.list_campaigns(min(plan.limit, MAX_CONTEXT_CAMPAIGNS))
    elif plan.intent == "campaign_detail":
        value = retrieval.get_campaign_by_id(filters["campaign_id"])
        campaigns = [value] if value else []
    elif plan.intent == "campaign_relationship":
        relationships = retrieval.get_campaign_relationships(
            filters.get("incident_ids", []), int(filters.get("minimum_matches", 2))
        )
        campaigns = [value.campaign for value in relationships]
        context["relationships"] = [
            {"campaign_id": value.campaign.campaign_id,
             "matching_incident_ids": list(value.matching_incident_ids)}
            for value in relationships
        ]
        aggregate_records_considered = len(filters.get("incident_ids", []))
    elif plan.intent == "highest_cvss":
        values = retrieval.get_highest_cvss_incidents(requested)
        context["cvss"] = [_json_value(value) for value in values]
    elif plan.intent == "cvss_severity":
        values = retrieval.search_incidents_by_cvss_severity(filters["severity"], requested)
        context["cvss"] = [_json_value(value) for value in values]
    elif plan.intent == "mitre_summary":
        context["mitre"] = _json_value(retrieval.get_mitre_summary())
    elif plan.intent == "mitre_technique":
        incidents = retrieval.search_incidents_by_mitre_technique(filters["technique"], requested)
    elif plan.intent == "mitre_tactic":
        incidents = retrieval.search_incidents_by_mitre_tactic(filters["tactic"], requested)
    elif plan.intent == "kill_chain_stage":
        incidents = retrieval.search_incidents_by_kill_chain_stage(filters["stage"], requested)
    elif plan.intent == "control_summary":
        context["controls"] = _json_value(retrieval.get_control_summary())
    elif plan.intent == "control_lookup":
        incidents = (retrieval.search_incidents_by_control_id(filters["control_id"], requested)
                     if "control_id" in filters else retrieval.search_incidents_by_control_title(filters["title"], requested))
    elif plan.intent == "control_framework":
        incidents = retrieval.search_incidents_by_control_framework(filters["framework"], requested)
    elif plan.intent == "soc_overview":
        context["summary"] = {"incident_count": retrieval.count_incidents()}
        incidents = retrieval.get_recent_incidents(5) + retrieval.get_high_severity_incidents(5)
        incidents = list({item.event_id: item for item in incidents}.values())[:MAX_CONTEXT_INCIDENTS]
        campaigns = retrieval.list_campaigns(5)
        context["cvss"] = [_json_value(value) for value in retrieval.get_highest_cvss_incidents(5)]
        context["mitre"] = _json_value(retrieval.get_mitre_summary())
        context["controls"] = _json_value(retrieval.get_control_summary())

    list_intents = {
        "recent_incidents", "high_severity_incidents", "source_ip_activity",
        "destination_ip_activity", "user_activity", "asset_activity", "status_filter",
        "threat_type_filter", "mitre_technique", "mitre_tactic", "kill_chain_stage",
        "control_lookup", "control_framework",
    }
    if plan.intent in list_intents and len(incidents) >= requested:
        state["truncated"] = True
    if plan.intent == "campaign_list" and len(campaigns) >= min(plan.limit, MAX_CONTEXT_CAMPAIGNS):
        state["truncated"] = True
    if len(incidents) > MAX_CONTEXT_INCIDENTS:
        incidents = incidents[:MAX_CONTEXT_INCIDENTS]
        state["truncated"] = True
    if len(campaigns) > MAX_CONTEXT_CAMPAIGNS:
        campaigns = campaigns[:MAX_CONTEXT_CAMPAIGNS]
        state["truncated"] = True
    if incidents:
        context["incidents"] = [_incident(value, state) for value in incidents]
    if campaigns:
        context["campaigns"] = [_campaign(value, state) for value in campaigns]

    evidence = ([{"type": "incident", "id": value.event_id} for value in incidents]
                + [{"type": "campaign", "id": value.campaign_id} for value in campaigns])
    rankings = context.get("rankings") or {}
    for section, kind in ((rankings.get("users", []), "user"),
                          (rankings.get("source_ips", []), "source_ip"),
                          (rankings.get("threat_types", []), "threat_type")):
        evidence.extend({"type": kind, "id": item["value"]} for item in section if item.get("value"))
    for section, kind, id_key in ((context.get("cvss", []), "incident", "event_id"),):
        evidence.extend({"type": kind, "id": item[id_key]} for item in section if item.get(id_key))
    mitre_context = context.get("mitre") or {}
    for item in mitre_context.get("techniques", []):
        identifier = item.get("technique_id") or item.get("name")
        if identifier:
            evidence.append({"type": "mitre_technique", "id": identifier})
    control_context = context.get("controls") or {}
    for item in control_context.get("controls", []):
        identifier = item.get("control_id") or item.get("title")
        if identifier:
            evidence.append({"type": "control", "id": identifier})
    unique = []
    seen = set()
    for item in evidence:
        key = (item["type"], item["id"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    if len(unique) > MAX_EVIDENCE_ITEMS:
        state["truncated"] = True
    context["evidence"] = unique[:MAX_EVIDENCE_ITEMS]
    context["facts"] = build_canonical_facts(context)
    context["metadata"] = {
        "records_considered": (aggregate_records_considered + len(incidents) + len(campaigns)
                               + len(context.get("cvss", []))),
        "evidence_count": len(context["evidence"]),
        "truncated": state["truncated"],
    }
    return context
