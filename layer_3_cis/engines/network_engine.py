from copy import deepcopy

from layer_3_cis.benchmark_matcher import retrieve_benchmarks


def process_network_event(entry: dict) -> dict:
    enriched = deepcopy(entry)

    raw_event = entry.get("raw_event", {}) or {}
    threat = entry.get("engine_2_threat_intel", {}) or {}
    correlation = entry.get("engine_3_correlation", {}) or {}

    port = raw_event.get("port")
    protocol = str(raw_event.get("protocol", "") or "").lower()
    mitre_tactic = str(threat.get("mitre_tactic", "") or "").lower()
    mitre_name = str(threat.get("mitre_technique_name", "") or "").lower()

    query_tags = []
    query_keywords = []
    section_hint = []

    if port == 22:
        query_tags.extend(["ssh", "authentication", "remote_access"])
        query_keywords.extend(["ssh", "port 22"])
        section_hint.extend(["ssh", "authentication"])

    if protocol:
        query_keywords.append(protocol)

    if "recon" in mitre_tactic or "scan" in mitre_name:
        query_tags.extend(["reconnaissance", "service_exposure"])
        query_keywords.extend(["scan", "reconnaissance"])

    timeline = correlation.get("attack_timeline", []) or []
    if timeline:
        query_keywords.extend(["firewall", "network access"])

    matched = retrieve_benchmarks(
        domain="network",
        query_tags=query_tags,
        query_keywords=query_keywords,
        section_hint=section_hint,
        max_results=1
    )

    enriched["cis_benchmark"] = {
        "framework": "network_controls_catalog",
        "retrieval_query": {
            "query_tags": query_tags,
            "query_keywords": query_keywords,
            "section_hint": section_hint,
        },
        "matched_benchmarks": matched
    }

    return enriched
