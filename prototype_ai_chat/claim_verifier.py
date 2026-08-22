"""Deterministic fact construction and verification for Gemini claims."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

MAX_FACTS = 120
CAUTIOUS_TERMS = ("may", "suggest", "consistent with", "warrant", "could", "possible")
ABSTENTION_TERMS = ("do not establish", "does not establish", "not established", "unknown", "not identify")
ASSESSMENT_FIELDS = {
    "severity", "threat_type", "verdict", "campaign_severity", "cvss_severity",
}
STRICT_FIELDS = {
    "incident_exists", "campaign_exists", "timestamp", "status", "source_ip",
    "destination_ip", "affected_user", "affected_host", "confidence", "severity",
    "threat_type", "verdict", "cvss_score", "cvss_severity", "mitre_tactic",
    "mitre_technique", "kill_chain_stage", "control_id", "control_title",
    "campaign_membership", "campaign_severity", "campaign_progression",
    "incident_count", "total_incidents", "critical_count", "high_count",
    "max_cvss", "latest_activity", "rank",
}
PROHIBITED_UNLESS_EXPLICIT = {
    "attribution", "malware_family", "cve", "financial_loss", "regulatory_requirement",
    "law_enforcement_notification", "confirmed_compromise", "confirmed_exfiltration",
    "data_stolen", "data_type", "data_quantity", "customer_exposure",
}


class ClaimStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    INVALID_REFERENCE = "INVALID_REFERENCE"
    CONTRADICTED = "CONTRADICTED"


@dataclass(frozen=True)
class VerifiedClaim:
    status: ClaimStatus
    classification: str
    claim_type: str
    subject: str | None
    value: Any
    text: str
    supporting_fact_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerificationResult:
    claims: tuple[VerifiedClaim, ...]
    claims_generated: int
    claims_supported: int
    claims_rejected: int
    claims_contradicted: int
    invalid_fact_references: int


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return abs(float(left) - float(right)) < 1e-9
    return str(left).strip().casefold() == str(right).strip().casefold()


def _append(facts: list[dict[str, Any]], category: str, field: str, value: Any,
            evidence_ids: Iterable[str], subject: str | None = None) -> None:
    if value is None or value == "" or value == [] or len(facts) >= MAX_FACTS:
        return
    facts.append({
        "fact_id": f"F{len(facts) + 1:03d}",
        "category": category,
        "field": field,
        "subject": subject,
        "value": value,
        "evidence_ids": list(dict.fromkeys(str(item) for item in evidence_ids if item)),
    })


def build_canonical_facts(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Create bounded canonical facts only from normalized deterministic context."""
    facts: list[dict[str, Any]] = []
    summary = context.get("summary") or {}
    if "incident_count" in summary:
        _append(facts, "aggregate", "incident_count", summary["incident_count"], [])

    for incident in context.get("incidents") or []:
        event_id = incident.get("event_id")
        if not event_id:
            continue
        _append(facts, "incident", "incident_exists", True, [event_id], event_id)
        for key in ("timestamp", "status", "source_ip", "destination_ip", "affected_user",
                    "affected_host", "confidence", "severity", "threat_type", "verdict"):
            _append(facts, "incident", key, incident.get(key), [event_id], event_id)
        cvss = incident.get("cvss") or {}
        _append(facts, "cvss", "cvss_score", cvss.get("score"), [event_id], event_id)
        _append(facts, "cvss", "cvss_severity", cvss.get("severity"), [event_id], event_id)
        mitre = incident.get("mitre") or {}
        for tactic in mitre.get("tactics") or []:
            _append(facts, "mitre", "mitre_tactic", tactic, [event_id], event_id)
        for technique in mitre.get("techniques") or []:
            value = technique.get("technique_id") or technique.get("name")
            _append(facts, "mitre", "mitre_technique", value, [event_id], event_id)
        _append(facts, "mitre", "kill_chain_stage", mitre.get("kill_chain_stage"), [event_id], event_id)
        for control in incident.get("controls") or []:
            _append(facts, "control", "control_id", control.get("control_id"), [event_id], event_id)
            _append(facts, "control", "control_title", control.get("title"), [event_id], event_id)

    for item in context.get("cvss") or []:
        event_id = item.get("event_id")
        _append(facts, "cvss", "cvss_score", item.get("cvss_score"), [event_id], event_id)
        _append(facts, "cvss", "cvss_severity", item.get("cvss_severity"), [event_id], event_id)

    for campaign in context.get("campaigns") or []:
        campaign_id = campaign.get("campaign_id")
        if not campaign_id:
            continue
        _append(facts, "campaign", "campaign_exists", True, [campaign_id], campaign_id)
        _append(facts, "campaign", "campaign_severity", campaign.get("severity"), [campaign_id], campaign_id)
        _append(facts, "campaign", "campaign_progression", campaign.get("progression_pct"), [campaign_id], campaign_id)
        for event_id in campaign.get("incident_ids") or []:
            _append(facts, "campaign", "campaign_membership", campaign_id,
                    [campaign_id, event_id], event_id)

    for relationship in context.get("relationships") or []:
        campaign_id = relationship.get("campaign_id")
        for event_id in relationship.get("matching_incident_ids") or []:
            _append(facts, "campaign", "campaign_membership", campaign_id,
                    [campaign_id, event_id], event_id)

    rankings = context.get("rankings") or {}
    for section, category in (("users", "user"), ("source_ips", "source_ip"),
                              ("threat_types", "threat_type")):
        for rank, item in enumerate(rankings.get(section) or [], 1):
            subject = item.get("value")
            if not subject:
                continue
            _append(facts, category, "rank", rank, [subject], subject)
            for key in ("total_incidents", "critical_count", "high_count", "max_cvss", "latest_activity"):
                _append(facts, category, key, item.get(key), [subject], subject)

    mitre = context.get("mitre") or {}
    for item in mitre.get("techniques") or []:
        identifier = item.get("technique_id") or item.get("name")
        _append(facts, "mitre", "mitre_technique", identifier, [identifier], identifier)
        _append(facts, "aggregate", "incident_count", item.get("count"), [identifier], identifier)
    controls = context.get("controls") or {}
    for item in controls.get("controls") or []:
        identifier = item.get("control_id") or item.get("title")
        _append(facts, "control", "control_id", item.get("control_id"), [identifier], identifier)
        _append(facts, "aggregate", "incident_count", item.get("incident_count"), [identifier], identifier)
    return facts


def parse_structured_response(raw: str) -> dict[str, Any]:
    candidate = raw.strip()
    if candidate.startswith("```") and candidate.endswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*|\s*```$", "", candidate, flags=re.IGNORECASE)
    value = json.loads(candidate)
    if not isinstance(value, dict) or not isinstance(value.get("claims"), list):
        raise ValueError("Gemini response does not match the structured claim contract.")
    return value


def verify_claims(output: dict[str, Any], facts: list[dict[str, Any]],
                  evidence_ids: set[str]) -> VerificationResult:
    fact_map = {fact["fact_id"]: fact for fact in facts}
    verified: list[VerifiedClaim] = []
    invalid = contradicted = supported = 0
    raw_claims = output.get("claims") if isinstance(output, dict) else []
    if not isinstance(raw_claims, list):
        raw_claims = []
    for raw in raw_claims[:40]:
        if not isinstance(raw, dict):
            continue
        classification = str(raw.get("classification") or "").casefold()
        claim_type = str(raw.get("claim_type") or "").casefold()
        subject = str(raw["subject"]) if raw.get("subject") is not None else None
        value = raw.get("value")
        text = str(raw.get("text") or "").strip()
        refs = tuple(str(item) for item in raw.get("supporting_fact_ids") or [])
        referenced_evidence = {str(item) for item in raw.get("evidence_ids") or []}
        status = ClaimStatus.UNSUPPORTED
        if any(ref not in fact_map for ref in refs) or not referenced_evidence.issubset(evidence_ids):
            status = ClaimStatus.INVALID_REFERENCE
            invalid += 1
        elif classification == "unknown":
            status = (ClaimStatus.SUPPORTED if any(term in text.casefold() for term in ABSTENTION_TERMS)
                      else ClaimStatus.UNSUPPORTED)
        elif not refs:
            status = ClaimStatus.UNSUPPORTED
        else:
            supporting = [fact_map[ref] for ref in refs]
            matching_type = [fact for fact in supporting if fact["field"] == claim_type]
            exact = [fact for fact in matching_type
                     if (subject is None or fact.get("subject") == subject or subject in fact.get("evidence_ids", []))
                     and _same(fact.get("value"), value)]
            competing = [fact for fact in facts if fact["field"] == claim_type
                         and (subject is None or fact.get("subject") == subject)]
            if claim_type in PROHIBITED_UNLESS_EXPLICIT and not exact:
                status = ClaimStatus.CONTRADICTED if competing else ClaimStatus.UNSUPPORTED
            elif classification in {"observed", "sentra_assessment"}:
                if exact:
                    status = ClaimStatus.SUPPORTED
                    if classification == "observed" and claim_type in ASSESSMENT_FIELDS:
                        classification = "sentra_assessment"
                elif competing or claim_type in STRICT_FIELDS:
                    status = ClaimStatus.CONTRADICTED
                else:
                    status = ClaimStatus.UNSUPPORTED
            elif classification == "inference":
                safe_type = claim_type in {"analyst_priority", "investigation_recommendation", "pattern_interpretation"}
                cautious = any(term in text.casefold() for term in CAUTIOUS_TERMS)
                status = ClaimStatus.SUPPORTED if safe_type and cautious and supporting else ClaimStatus.UNSUPPORTED
            if status == ClaimStatus.CONTRADICTED:
                contradicted += 1
        if status == ClaimStatus.SUPPORTED:
            supported += 1
        verified.append(VerifiedClaim(status, classification, claim_type, subject, value, text, refs))
    generated = len(verified)
    return VerificationResult(
        tuple(verified), generated, supported, generated - supported, contradicted, invalid,
    )


def render_verified_answer(result: VerificationResult) -> str | None:
    groups = {"observed": [], "sentra_assessment": [], "inference": [], "unknown": []}
    labels = {
        "incident_exists": "Incident", "campaign_exists": "Campaign", "severity": "severity",
        "threat_type": "threat type", "verdict": "verdict", "timestamp": "timestamp",
        "status": "status", "source_ip": "source IP", "destination_ip": "destination IP",
        "affected_user": "affected user", "affected_host": "affected asset",
        "cvss_score": "CVSS score", "cvss_severity": "CVSS severity",
        "mitre_tactic": "MITRE tactic", "mitre_technique": "MITRE technique",
        "control_id": "control", "control_title": "control title",
        "campaign_membership": "campaign membership", "campaign_severity": "campaign severity",
        "campaign_progression": "campaign progression", "incident_count": "incident count",
        "total_incidents": "total incidents", "critical_count": "Critical incidents",
        "high_count": "High incidents", "max_cvss": "maximum CVSS", "rank": "rank",
    }
    for claim in result.claims:
        if claim.status != ClaimStatus.SUPPORTED:
            continue
        subject = claim.subject or "SENTRA records"
        if claim.classification == "unknown":
            safe_text = "The available SENTRA records do not establish the requested detail."
        elif claim.classification == "inference":
            safe_text = f"The supported evidence warrants further analyst investigation of {subject}."
        else:
            label = labels.get(claim.claim_type, claim.claim_type.replace("_", " "))
            if claim.claim_type == "incident_exists":
                safe_text = f"Incident {subject} exists in the supplied SENTRA evidence."
            elif claim.claim_type == "campaign_exists":
                safe_text = f"Campaign {subject} exists in the supplied SENTRA evidence."
            elif claim.classification == "sentra_assessment":
                safe_text = f"SENTRA assesses {subject} with {label} {claim.value}."
            else:
                safe_text = f"{subject}: {label} = {claim.value}."
        groups.setdefault(claim.classification, []).append(safe_text)
    if not any(groups.values()):
        return None
    headings = {
        "observed": "Observed evidence", "sentra_assessment": "SENTRA assessment",
        "inference": "Analyst interpretation", "unknown": "Unknown / not established",
    }
    sections = []
    for key in ("observed", "sentra_assessment", "inference", "unknown"):
        if groups[key]:
            sections.append(headings[key] + "\n" + "\n".join(f"- {text}" for text in groups[key]))
    return "\n\n".join(sections)


def deterministic_fact_summary(facts: list[dict[str, Any]]) -> str:
    useful = []
    labels = {
        "incident_exists": "Incident", "campaign_exists": "Campaign", "severity": "Severity",
        "threat_type": "Threat type", "cvss_score": "CVSS", "affected_user": "User",
        "affected_host": "Asset", "source_ip": "Source IP", "destination_ip": "Destination IP",
        "incident_count": "Incident count", "mitre_technique": "MITRE technique",
        "control_id": "Control", "campaign_membership": "Campaign membership",
        "total_incidents": "Total incidents", "critical_count": "Critical incidents",
        "high_count": "High incidents", "max_cvss": "Maximum CVSS",
    }
    for fact in facts:
        label = labels.get(fact["field"])
        if not label:
            continue
        value = fact.get("subject") if fact["field"] in {"incident_exists", "campaign_exists"} else fact["value"]
        line = f"- {label}: {value}"
        if line not in useful:
            useful.append(line)
        if len(useful) >= 8:
            break
    if not useful:
        return "The available SENTRA records do not establish the requested detail."
    return ("Based on the available SENTRA evidence:\n" + "\n".join(useful)
            + "\n\nThe available evidence does not establish additional details.")
