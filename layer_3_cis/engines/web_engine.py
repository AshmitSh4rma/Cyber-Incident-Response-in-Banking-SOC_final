from copy import deepcopy
from layer_3_cis.benchmark_matcher import retrieve_benchmarks


def process_web_event(entry: dict) -> dict:
    enriched = deepcopy(entry)
    raw_event = entry.get("raw_event", {}) or {}
    threat = entry.get("engine_2_threat_intel", {}) or {}
    correlation = entry.get("engine_3_correlation", {}) or {}
    detection = entry.get("detection", {}) or {}

    # Pull from MORE fields, not just mitre_technique_name
    mitre_name = str(threat.get("mitre_technique_name", "") or "").lower()
    mitre_tactic = str(threat.get("mitre_tactic", "") or "").lower()
    threat_type = str(detection.get("threat_type", "") or "").lower()
    label = str(detection.get("label", "") or "").lower()
    host = str(raw_event.get("affected_host", "") or "").lower()

    query_tags = ["web_application", "application_security"]  # Always start with base tags
    query_keywords = ["web", "application"]
    section_hint = []

    # Use ALL available fields as signal
    combined_signal = f"{mitre_name} {mitre_tactic} {threat_type} {label}"

    if any(w in combined_signal for w in ["inject", "sqli", "xss", "traversal"]):
        query_tags.extend(["injection", "input_validation"])
        query_keywords.extend(["sql injection", "injection", "xss"])
        section_hint.append("injection")

    if any(w in combined_signal for w in ["auth", "credential", "login", "brute", "password"]):
        query_tags.extend(["authentication", "login", "credential_security"])
        query_keywords.extend(["login", "authentication", "brute force"])
        section_hint.append("authentication")

    if any(w in combined_signal for w in ["dos", "flood", "rate", "exhaustion"]):
        query_tags.extend(["availability", "rate_limiting", "dos_protection"])
        section_hint.append("availability")

    timeline = correlation.get("attack_timeline", []) or []
    if timeline:
        for item in timeline:
            detail = str(item.get("detail", "") or "").lower()
            if "login" in detail or "failed" in detail or "authentication" in detail:
                query_tags.extend(["authentication", "login_abuse"])
                query_keywords.extend(["login", "failed authentication"])
                section_hint.extend(["authentication"])

    matched = retrieve_benchmarks(
        domain="web",
        query_tags=query_tags,
        query_keywords=query_keywords,
        section_hint=section_hint,
        max_results=1
    )

    enriched["cis_benchmark"] = {
        "framework": "web_owasp_catalog",
        "retrieval_query": {
            "query_tags": query_tags,
            "query_keywords": query_keywords,
            "section_hint": section_hint,
        },
        "matched_benchmarks": matched
    }

    return enriched