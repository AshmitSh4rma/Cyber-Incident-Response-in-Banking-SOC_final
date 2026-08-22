from copy import deepcopy

from layer_3_cis.benchmark_matcher import retrieve_benchmarks

# ─────────────────────────────────────────────────────────────────────────────
# Management protocols that carry credentials in the clear. A branch camera or
# ATM reachable over any of these is a finding on its own, before anyone
# attacks it.
# ─────────────────────────────────────────────────────────────────────────────
CLEARTEXT_PROTOCOLS = {"telnet", "ftp", "http", "snmp", "tftp", "rlogin", "rsh"}

CLEARTEXT_PORTS = {23: "telnet", 21: "ftp", 69: "tftp", 161: "snmp", 513: "rlogin", 514: "rsh"}


def process_iot_event(entry: dict) -> dict:
    """
    Map an IoT/OT device event to network hardening controls.

    These events are retrieved against the *network* catalogue rather than a
    device-specific one. A bank's IoT estate is branch cameras, ATMs, badge
    readers and sensors — appliances whose security posture is decided by how
    the network treats them (is Telnet disabled, is management authenticated,
    is the segment isolated), not by settings on the device. The network
    catalogue holds those controls; the mobile-device benchmark that used to be
    wired in here held iOS and Android privacy settings, which no bank camera
    has.
    """
    enriched = deepcopy(entry)

    raw_event = entry.get("raw_event", {}) or {}
    anomaly = entry.get("engine_1_anomaly", {}) or {}
    threat = entry.get("engine_2_threat_intel", {}) or {}

    ueba_flags = [str(x).lower() for x in (anomaly.get("ueba_flags") or [])]
    mitre_technique = str(threat.get("mitre_technique", "") or "").lower()
    mitre_name = str(threat.get("mitre_technique_name", "") or "").lower()

    protocol = str(raw_event.get("protocol", "") or "").lower()
    try:
        port = int(raw_event.get("port")) if raw_event.get("port") is not None else None
    except (TypeError, ValueError):
        port = None

    query_tags: list[str] = []
    query_keywords: list[str] = []
    section_hint: list[str] = []

    # ── Cleartext management access — the dominant IoT finding ────────────────
    cleartext = protocol if protocol in CLEARTEXT_PROTOCOLS else CLEARTEXT_PORTS.get(port)
    if cleartext:
        query_tags.extend(["remote_access", "authentication", "management_plane"])
        query_keywords.append(cleartext)
        section_hint.extend(["management", "authentication", "remote access"])

    # ── Any other management protocol still narrows the search ────────────────
    elif protocol:
        query_tags.extend(["remote_access", "management_plane"])
        query_keywords.append(protocol)

    if "off_hours_activity" in ueba_flags:
        query_tags.extend(["monitoring", "logging", "anomalous_access"])
        query_keywords.extend(["logging", "audit"])

    if mitre_technique in {"t1078", "t1552"} or "valid accounts" in mitre_name:
        query_tags.extend(["authentication", "credentials", "valid_accounts"])
        query_keywords.extend(["password", "local user"])
        section_hint.extend(["authentication", "access control"])

    matched = retrieve_benchmarks(
        domain="network",
        query_tags=query_tags,
        query_keywords=query_keywords,
        section_hint=section_hint,
        max_results=1,
    )

    enriched["cis_benchmark"] = {
        "framework": "network_controls_catalog",
        "retrieval_query": {
            "query_tags": query_tags,
            "query_keywords": query_keywords,
            "section_hint": section_hint,
        },
        "matched_benchmarks": matched,
    }

    return enriched
