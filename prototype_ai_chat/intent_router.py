"""Deterministic routing of common SOC questions into retrieval plans."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

DEFAULT_PLAN_LIMIT = 10
GENERAL_SECURITY_TERMS = (
    "soc", "security operations center", "soc analyst", "siem", "soar", "edr", "xdr",
    "ids", "ips", "firewall", "waf", "mitre att&ck", "cvss", "cve", "ioc", "iocs",
    "indicator of compromise", "threat intelligence", "threat hunting", "threat detection",
    "alert triage", "incident triage", "incident response", "security incident", "security alert",
    "log analysis", "security log", "audit log", "telemetry", "detection rule", "correlation rule",
    "use case", "playbook", "runbook", "blue team", "defensive security", "cybersecurity",
    "network security", "endpoint security", "cloud security", "email security", "identity security",
    "authentication", "authorization", "access control", "least privilege", "zero trust", "mfa",
    "multi-factor", "failed login", "failed logins", "suspicious login", "login anomaly",
    "password spray", "brute force", "credential access", "lateral movement",
    "privilege escalation", "persistence", "command and control", "data exfiltration", "dlp",
    "phishing", "malware", "ransomware", "trojan", "rootkit", "botnet", "cyber attack", "web attack",
    "sql injection", "cross-site scripting", "xss", "path traversal", "denial of service", "ddos",
    "vulnerability", "vulnerability management", "patch management", "risk assessment",
    "attack surface", "attack vector", "kill chain", "containment", "eradication", "recovery",
    "digital forensics", "forensic", "nist", "iso 27001", "cis control", "owasp",
    "security control", "compliance", "false positive", "true positive", "severity", "confidence",
)
THREAT_TYPE_ALIASES = (
    (("sql injection", "sql-injection", "sql_injection", "web attack"), "web_attack", "SQL injection-related"),
    (("brute force", "brute-force", "bruteforce"), "brute_force_attempt", "brute-force"),
    (("credential attack", "credential attacks", "credential abuse"), "credential_abuse", "credential-attack"),
    (("network scan", "port scan", "reconnaissance"), "port_scan", "network-scan"),
    (("data exfiltration", "exfiltration"), "data_exfiltration", "data-exfiltration"),
    (("lateral movement",), "lateral_movement", "lateral-movement"),
    (("suspicious login",), "suspicious_login_behavior", "suspicious-login"),
    (("beaconing", "command and control"), "beaconing", "beaconing"),
)
SUPPORTED_INTENTS = frozenset(
    {
        "incident_count", "recent_incidents", "high_severity_incidents",
        "incident_detail", "campaign_list", "campaign_detail",
        "source_ip_activity", "destination_ip_activity", "user_activity",
        "asset_activity", "status_filter", "threat_type_filter",
        "highest_cvss", "cvss_severity", "mitre_summary", "mitre_technique",
        "mitre_tactic", "kill_chain_stage", "control_summary",
        "control_lookup", "control_framework", "soc_overview", "unknown",
        "sample_incident", "highest_risk_incident", "filtered_incident_count",
        "top_risky_users", "top_risky_ips", "top_threat_types", "campaign_relationship",
        "greeting", "capabilities", "general_security",
        "out_of_scope",
    }
)


@dataclass(frozen=True)
class RetrievalPlan:
    intent: str
    filters: dict[str, Any] = field(default_factory=dict)
    limit: int = DEFAULT_PLAN_LIMIT
    confidence: float = 1.0
    matched_entities: dict[str, str] = field(default_factory=dict)


def _relative_time(text: str, now: datetime) -> dict[str, str]:
    current = now.astimezone(UTC)
    if re.search(r"\b(?:last|past)(?:\s+1)?\s+hour\b", text):
        start = current - timedelta(hours=1)
    elif re.search(r"\b(last 24 hours|past 24 hours|last day|past day)\b", text):
        start = current - timedelta(days=1)
    elif re.search(r"\b(last|past) 7 days\b|\blast week\b", text):
        start = current - timedelta(days=7)
    elif re.search(r"\byesterday\b", text):
        end = current.replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=1)
        return {
            "start": start.isoformat().replace("+00:00", "Z"),
            "end": end.isoformat().replace("+00:00", "Z"),
        }
    elif re.search(r"\btoday\b", text):
        start = current.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        return {}
    return {
        "start": start.isoformat().replace("+00:00", "Z"),
        "end": current.isoformat().replace("+00:00", "Z"),
    }


def _extract_ip(question: str) -> str | None:
    for token in re.findall(r"(?<![\w.:-])(?:[0-9A-Fa-f:.]+)(?![\w.:-])", question):
        try:
            return str(ip_address(token.strip("[]")))
        except ValueError:
            continue
    return None


def _match_value(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip(" .?!,'\"") if match else None


def _threat_alias(text: str) -> tuple[str, str] | None:
    normalized = text.replace("_", " ")
    for aliases, stored_value, label in THREAT_TYPE_ALIASES:
        if any(re.search(rf"\b{re.escape(alias)}\b", normalized) for alias in aliases):
            return stored_value, label
    return None


def route_intent(question: str, *, now: datetime | None = None) -> RetrievalPlan:
    """Route by explicit priority: identifiers/entities before broad summaries."""
    if not isinstance(question, str) or not question.strip():
        return RetrievalPlan("unknown", confidence=0.0)
    raw = question.strip()
    text = re.sub(r"\s+", " ", raw.casefold()).strip()
    for source, target in {
        "dangrous": "dangerous", "suspcious": "suspicious", "critcal": "critical",
        "injecton": "injection", "breifing": "briefing", "happning": "happening",
    }.items():
        text = re.sub(rf"\b{source}\b", target, text)
    text = re.sub(r"\b24\s*h(?:r|rs)?\b", "24 hours", text)
    text = re.sub(r"\bhrs?\b", "hours", text)
    text = re.sub(r"\b(last|past)\s+1\s+hours\b", r"\1 hour", text)
    text = re.sub(r"\b(last|past)\s+hours\b", r"\1 hour", text)
    # Narrow conversational aliases only; this is not fuzzy intent matching.
    match_text = re.sub(r"\banyone\s+logs?\b", "any one log", text)
    match_text = re.sub(r"\blogs\b", "log", match_text)
    current = now or datetime.now(UTC)
    time_filters = _relative_time(text, current)
    count_requested = bool(
        re.search(r"\bhow\s+many\b", text)
        or re.search(r"\btotal\s+(?:log|logs|incident|incidents|attack|attacks|threat|threats|alert|alerts|record|records|security records|security events)\b", text)
    )
    threat_alias = _threat_alias(text)

    if re.search(
        r"\b(?:which|what)\s+(?:user|account)\b.*\b(?:most trouble|most suspicious|investigate|highest risk)\b|"
        r"\b(?:who)\b.*\bmost dangerous activity\b|\btop suspicious users?\b|"
        r"\b(?:show me\s+)?(?:the\s+)?riskiest users?\b",
        text,
    ):
        return RetrievalPlan("top_risky_users", limit=5)

    if re.search(
        r"\b(?:which|what)\s+(?:external\s+|source\s+)?ip\b.*\b(?:dangerous|worry|trouble)\b|"
        r"\b(?:most suspicious|riskiest|dangerous|most dangerous)\s+(?:source\s+|external\s+)?ip\b|"
        r"\bshow\s+(?:me\s+)?(?:the\s+)?most dangerous ip\b",
        text,
    ):
        return RetrievalPlan("top_risky_ips", limit=5)

    explicit_incident_id = _match_value(raw, r"\bincident\s+(?:id\s+)?([A-Za-z0-9][A-Za-z0-9_.:-]*)")
    bare_incident_id = _match_value(raw, r"\b((?:SYN|EVT)-[A-Za-z0-9_.:-]+)\b")
    incident_id = bare_incident_id or explicit_incident_id
    if incident_id and (bare_incident_id or any(
        word in text for word in ("explain", "show", "detail", "about", "what")
    )):
        return RetrievalPlan("incident_detail", {"event_id": incident_id}, matched_entities={"event_id": incident_id})
    campaign_id = (_match_value(raw, r"\bcampaign\s+(?:id\s+)?(CMP-[A-Za-z0-9_.:-]+)")
                   or _match_value(raw, r"\b(CMP-[A-Za-z0-9_.:-]+)\b"))
    if campaign_id:
        return RetrievalPlan("campaign_detail", {"campaign_id": campaign_id}, matched_entities={"campaign_id": campaign_id})

    technique = _match_value(raw, r"\b(T\d{4}(?:\.\d{3})?)\b")
    if technique:
        technique = technique.upper()
        return RetrievalPlan("mitre_technique", {"technique": technique}, matched_entities={"technique": technique})

    ip_value = _extract_ip(raw)
    if ip_value:
        if count_requested:
            return RetrievalPlan(
                "filtered_incident_count", {"source_ip": ip_value}, limit=0,
                matched_entities={"filter_label": f"source IP {ip_value}"},
            )
        destination = bool(re.search(r"\b(destination|dest(?:ination)?|to)\b", text))
        intent = "destination_ip_activity" if destination else "source_ip_activity"
        key = "destination_ip" if destination else "source_ip"
        return RetrievalPlan(intent, {key: ip_value, **time_filters}, matched_entities={key: ip_value})

    if re.search(r"\bwhich\s+(?:user|account).+\bmost\s+(?:attack|attacks|incident|incidents)\b", text):
        return RetrievalPlan("out_of_scope", confidence=1.0)

    user = _match_value(raw, r"\b(?:user|account)\s+([A-Za-z0-9_.@-]+)")
    if not user and re.search(r"\b(?:compromised|suspicious|risk|involved)\b", text):
        user = _match_value(raw, r"\b([A-Za-z][A-Za-z0-9_-]*\.[A-Za-z0-9_.-]+)\b")
    if user:
        if count_requested:
            return RetrievalPlan(
                "filtered_incident_count", {"user": user}, limit=0,
                matched_entities={"filter_label": f"user {user}"},
            )
        return RetrievalPlan("user_activity", {"user": user, **time_filters}, matched_entities={"user": user})
    asset = _match_value(raw, r"\b(?:asset|host|device)\s+([A-Za-z0-9_.:-]+)")
    if count_requested and not asset:
        asset = _match_value(raw, r"\baffected(?:\s+(?:host|asset))?\s+([A-Za-z0-9_.:-]+)")
    if not asset and re.search(r"\b(?:attacks?|activity|threats?|suspicious|happened)\b", text):
        asset = _match_value(raw, r"\b((?:[A-Z][A-Z0-9]*-){2,}[A-Z0-9]+)\b")
    if asset:
        if count_requested:
            return RetrievalPlan(
                "filtered_incident_count", {"asset": asset}, limit=0,
                matched_entities={"filter_label": f"asset {asset}"},
            )
        return RetrievalPlan("asset_activity", {"asset": asset, **time_filters}, matched_entities={"asset": asset})

    top_threat_match = re.search(
        r"\btop\s+(?:(\d+)\s+)?(?:threats?|attacks?|threat types?)\b|"
        r"\bmost\s+(?:common|dangerous|serious)\s+(?:threats?|attack types?)\b|"
        r"\bwhat threats are we seeing most\b|\bwhich attack types are most serious\b",
        text,
    )
    if top_threat_match:
        requested_limit = int(top_threat_match.group(1) or DEFAULT_PLAN_LIMIT)
        return RetrievalPlan("top_threat_types", limit=max(1, min(requested_limit, 20)))

    if re.search(
        r"\b(?:are any of these attacks connected|are these incidents related|"
        r"do these belong to the same campaign|which of these are part of a campaign|"
        r"how are these attacks related)\b",
        text,
    ):
        return RetrievalPlan("campaign_list", limit=5)

    control_id = _match_value(raw, r"\b((?:CIS-[A-Za-z0-9.]+)|(?:OWASP-[A-Za-z0-9.]+))\b")
    if control_id:
        return RetrievalPlan("control_lookup", {"control_id": control_id}, matched_entities={"control_id": control_id})
    if "owasp" in text and re.search(r"\bcis\b", text):
        return RetrievalPlan("control_summary")
    if "owasp" in text:
        return RetrievalPlan("control_framework", {"framework": "OWASP"}, matched_entities={"framework": "OWASP"})
    if re.search(r"\bcis\b", text) and any(word in text for word in ("control", "benchmark", "relevant")):
        return RetrievalPlan("control_summary")

    tactic = _match_value(raw, r"\b(?:mitre\s+)?tactic\s+([A-Za-z][A-Za-z -]+?)(?:[?.!]|$)")
    if tactic:
        return RetrievalPlan("mitre_tactic", {"tactic": tactic}, matched_entities={"tactic": tactic})
    stage = _match_value(raw, r"\bkill[- ]chain\s+(?:stage\s+)?([A-Za-z][A-Za-z -]+?)(?:[?.!]|$)")
    if stage:
        return RetrievalPlan("kill_chain_stage", {"stage": stage}, matched_entities={"stage": stage})

    if any(phrase in text for phrase in ("what can you do", "how can you help", "what do you do", "your capabilities")):
        return RetrievalPlan("capabilities")

    if threat_alias and re.search(
        r"\b(?:give|show|explain|review)\b.*\b(?:one|a|an|any|latest|recent)\b.*"
        r"\b(?:incident|attack|event|log)\b",
        match_text,
    ):
        stored_type, label = threat_alias
        return RetrievalPlan(
            "threat_type_filter", {"threat_type": stored_type}, limit=1,
            matched_entities={"filter_label": label},
        )

    if re.search(r"\b(?:log|attack|security event)\b", match_text) and re.search(
        r"\b(?:overview\s+of\s+)?(?:a|an|any|any one|one|sample|random|recent|latest)\s+"
        r"(?:log|attack|security event)\b",
        match_text,
    ):
        return RetrievalPlan("sample_incident", limit=1)

    if count_requested and threat_alias:
        stored_type, label = threat_alias
        return RetrievalPlan(
            "filtered_incident_count", {"threat_type": stored_type}, limit=0,
            matched_entities={"filter_label": label},
        )

    definitional = bool(re.search(r"\b(what is|what are|what does|define|explain)\b", text))
    database_qualifier = any(
        phrase in text for phrase in ("our incident", "in our", "stored", "appearing", "show me", "current incident")
    )
    record_question = any(word in text for word in ("incident", "alert", "campaign", "record"))
    if definitional and not database_qualifier and not record_question and any(term in text for term in GENERAL_SECURITY_TERMS):
        return RetrievalPlan("general_security")

    cvss_severity = next((value for value in ("critical", "high", "medium", "low", "none") if re.search(rf"\b{value}\b", text)), None)
    if "cvss" in text:
        if cvss_severity and not any(word in text for word in ("highest", "top", "score")):
            return RetrievalPlan("cvss_severity", {"severity": cvss_severity})
        return RetrievalPlan("highest_cvss")
    if "mitre" in text or ("technique" in text and "control" not in text):
        return RetrievalPlan("mitre_summary")
    if any(word in text for word in ("control", "benchmark")):
        return RetrievalPlan("control_summary")

    status = next((value for value in ("investigating", "closed", "open") if re.search(rf"\b{value}\b", text)), None)
    severity = next((value for value in ("critical", "high", "medium", "low") if re.search(rf"\b{value}\b", text)), None)
    if count_requested and status:
        return RetrievalPlan(
            "filtered_incident_count", {"status": status}, limit=0,
            matched_entities={"filter_label": f"{status} status"},
        )
    if count_requested and severity:
        return RetrievalPlan(
            "filtered_incident_count", {"severity": severity}, limit=0,
            matched_entities={"filter_label": f"{severity} severity"},
        )
    if status and any(word in text for word in ("incident", "alert", "case")):
        return RetrievalPlan("status_filter", {"status": status})
    threat = _match_value(raw, r"\bthreat[- ]type\s+([A-Za-z0-9_-]+)")
    if threat:
        return RetrievalPlan("threat_type_filter", {"threat_type": threat})

    if count_requested and re.search(r"\b(?:log|logs|record|records|incident|incidents|attack|attacks|threat|threats|alert|alerts|security event|security events)\b", text):
        return RetrievalPlan("incident_count")
    if threat_alias and any(marker in text for marker in ("our", "we have", "with us", "database", "stored", "record", "log", "incident", "sentra", "detected", "show me")):
        stored_type, _ = threat_alias
        return RetrievalPlan("threat_type_filter", {"threat_type": stored_type})
    if any(phrase in text for phrase in ("worst attack", "worst incident", "highest risk attack", "highest risk incident")):
        return RetrievalPlan("highest_risk_incident", limit=1)
    if any(phrase in text for phrase in ("most severe", "most serious", "highest severity", "critical incident", "critical attack")):
        return RetrievalPlan("high_severity_incidents")
    if "campaign" in text:
        return RetrievalPlan("campaign_list")
    if time_filters or any(word in text for word in ("recent", "latest", "newest")):
        return RetrievalPlan("recent_incidents", time_filters)
    if any(phrase in text for phrase in ("soc briefing", "soc overview", "what's happening", "what is happening", "know right now", "investigate first")):
        return RetrievalPlan("soc_overview")
    if re.search(r"\b(?:show|list|display|review)\s+(?:me\s+)?(?:the\s+)?(?:security\s+)?(?:incident|alert|attack|threat)s?\b", text):
        return RetrievalPlan("recent_incidents", time_filters)
    if any(term in text for term in GENERAL_SECURITY_TERMS):
        return RetrievalPlan("general_security")
    if re.fullmatch(r"(?:why|which one|that incident|that campaign|what should i do next)[?.! ]*", text):
        return RetrievalPlan("unknown", confidence=0.0)
    greeting_text = re.sub(r"[^\w\s-]+", " ", text)
    greeting_text = re.sub(r"\s+", " ", greeting_text).strip()
    if re.fullmatch(
        r"(?:(?:hi|hello|hey)(?:\s+(?:there|sentra|lol))*|"
        r"good\s+(?:morning|afternoon|evening)(?:\s+(?:there|sentra))*)",
        greeting_text,
    ):
        return RetrievalPlan("greeting")
    return RetrievalPlan("out_of_scope", confidence=1.0)
