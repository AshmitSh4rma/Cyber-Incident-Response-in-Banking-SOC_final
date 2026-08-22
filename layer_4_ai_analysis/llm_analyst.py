"""
Optional LLM enrichment for Layer 4.

This used to be a LangGraph "agent". It was a single-node graph — entry point,
one function, END — wrapping one model call, which is framework theatre rather
than agency. The framework is gone; the capability it wrapped is here, stated
plainly.

Layer 4's job is to turn a detection into an analyst-readable incident: an intent,
a narrative, and the CVSS metrics Layer 5 needs. The deterministic path in
incident_report_builder does that on its own and is what runs in the demo. This
module is strictly an upgrade: when a local model is reachable, it writes a better
narrative. When it is not, nothing breaks and nothing is missing.

Every field the model returns is validated against the same closed vocabularies
the deterministic path uses, because a free-text "attack_vector": "kind of
networky" would silently corrupt the CVSS score downstream.
"""

from typing import Any

from json_parser import parse_llm_response
from ollama_client import run_inference

# Closed vocabularies. Layer 5 computes a CVSS base score from these, so an
# out-of-vocabulary value is not a cosmetic problem — it changes the number a
# regulator would see.
_ALLOWED = {
    "attack_vector": {"network", "adjacent", "local", "physical"},
    "attack_complexity": {"low", "high"},
    "privileges_required": {"none", "low", "high"},
    "user_interaction": {"none", "required"},
    "scope": {"unchanged", "changed"},
}
_ALLOWED_IMPACT = {"none", "low", "high"}

_REQUIRED_TEXT = ("intent", "summary", "narrative")


def _field(source: dict, *names: str, default: str = "") -> str:
    for name in names:
        value = source.get(name)
        if value not in (None, ""):
            return str(value)
    return default


def build_prompt(incident: dict) -> str:
    """
    Build the analysis prompt from an incident.

    Deliberately gives the model the facts and asks only for language and
    judgement. It is not asked to invent asset names or to pick a severity band —
    those are already decided by layers that can be held to account for them.
    """
    raw = incident.get("raw_event") or {}
    detection = incident.get("detection") or {}
    dash = incident.get("dashboard") or {}
    cis = incident.get("cis") or {}
    attack = incident.get("mitre_attack") or {}
    anomaly = incident.get("anomaly_detection") or {}
    ioc = incident.get("ioc_enrichment") or {}
    primary = attack.get("primary") or {}

    facts = [
        f"Source address: {_field(dash, 'source_ip') or _field(raw, 'source_ip', default='unknown')}",
        f"Destination: {_field(dash, 'destination_ip') or _field(raw, 'destination_ip', default='n/a')}",
        f"Affected host: {_field(dash, 'affected_host') or _field(raw, 'affected_host', default='unknown')}",
        f"Affected account: {_field(dash, 'affected_user', default='unattributed')}",
        f"Protocol / port: {_field(raw, 'protocol', default='n/a')} / {_field(raw, 'port', default='n/a')}",
        f"Request path: {_field(raw, 'url', 'url_path', default='n/a')}",
        f"Detection verdict: {_field(detection, 'label', default='suspicious')}",
        f"Threat type: {_field(detection, 'threat_type', default='unknown')}",
        f"Severity (already determined, do not change): {_field(detection, 'severity', default='low')}",
        f"Detection confidence: {detection.get('confidence', 'n/a')}",
        f"Anomaly score: {anomaly.get('anomaly_score', 'n/a')}",
        f"Threat intel match: {bool(ioc.get('matched'))}",
        f"ATT&CK technique: {_field(primary, 'technique_id')} {_field(primary, 'technique_name')}".strip(),
        f"Kill chain stage: {_field(attack, 'kill_chain_stage', default='unmapped')}",
        f"Relevant control: {_field(cis, 'benchmark_id')} — {_field(cis, 'title', default='none matched')}",
    ]

    return (
        "You are a senior SOC analyst at a retail bank. Write the analyst-facing "
        "write-up for the security event below and return ONE JSON object, no "
        "markdown, no commentary outside the JSON.\n\n"
        "EVENT FACTS (these are established; do not contradict them):\n"
        + "\n".join(f"- {f}" for f in facts)
        + "\n\nWrite for a reader who must decide what to do in the next five "
        "minutes. Reference the real host and account names above. Say what the "
        "business consequence would be if this succeeded, in terms a bank's risk "
        "officer would recognise.\n\n"
        "Also classify the event against CVSS 3.1 using EXACTLY these lowercase "
        "values and nothing else:\n"
        "- attack_vector: network | adjacent | local | physical\n"
        "- attack_complexity: low | high\n"
        "- privileges_required: none | low | high\n"
        "- user_interaction: none | required\n"
        "- scope: unchanged | changed\n"
        "- impact.confidentiality / integrity / availability: none | low | high\n\n"
        "Return exactly this shape:\n"
        "{\n"
        '  "intent": "what the attacker was trying to achieve",\n'
        '  "summary": "one sentence on what happened in this specific event",\n'
        '  "narrative": "2-4 sentences: what happened, what is affected, and the '
        'business consequence if it succeeded",\n'
        '  "attack_vector": "network",\n'
        '  "attack_complexity": "low",\n'
        '  "privileges_required": "none",\n'
        '  "user_interaction": "none",\n'
        '  "scope": "unchanged",\n'
        '  "impact": {"confidentiality": "high", "integrity": "low", "availability": "none"}\n'
        "}"
    )


def validate(candidate: Any) -> dict | None:
    """
    Accept the model's output only if it is complete and in-vocabulary.

    Returns the cleaned analysis, or None to fall back. Partial acceptance is
    deliberately not offered: an analysis with a plausible narrative and a
    garbage attack_vector is more dangerous than no analysis at all, because the
    narrative makes the bad metric look considered.
    """
    if not isinstance(candidate, dict):
        return None

    for key in _REQUIRED_TEXT:
        value = candidate.get(key)
        if not isinstance(value, str) or len(value.strip()) < 15:
            return None

    cleaned: dict[str, Any] = {key: candidate[key].strip() for key in _REQUIRED_TEXT}

    for key, allowed in _ALLOWED.items():
        value = str(candidate.get(key, "")).strip().lower()
        if value not in allowed:
            return None
        cleaned[key] = value

    impact = candidate.get("impact")
    if not isinstance(impact, dict):
        return None
    cleaned_impact = {}
    for dimension in ("confidentiality", "integrity", "availability"):
        value = str(impact.get(dimension, "")).strip().lower()
        if value not in _ALLOWED_IMPACT:
            return None
        cleaned_impact[dimension] = value
    cleaned["impact"] = cleaned_impact

    cleaned["source"] = "llm"
    return cleaned


def analyse(incident: dict) -> dict | None:
    """
    Run the model over one incident. Returns a validated analysis or None.

    Never raises: a Layer 4 that can crash the pipeline when a model misbehaves
    would make the optional dependency effectively mandatory.
    """
    try:
        result = run_inference(build_prompt(incident))
        if not result.get("success"):
            return None

        parsed = parse_llm_response(result.get("response") or "")
        if not parsed.get("parsed"):
            return None

        return validate(parsed.get("data"))
    except Exception:
        return None
