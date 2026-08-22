import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from llm_analyst import analyse as llm_analyse
from ollama_client import check_ollama_connection


# ─────────────────────────────────────────
# OLLAMA CONNECTION CACHING
# ─────────────────────────────────────────

_OLLAMA_OK: bool | None = None


def _is_ollama_available() -> bool:
    global _OLLAMA_OK
    if _OLLAMA_OK is None:
        result = check_ollama_connection(force_recheck=True)
        _OLLAMA_OK = result["connected"]
    return _OLLAMA_OK


# ─────────────────────────────────────────
# RULE-BASED FALLBACK
# ─────────────────────────────────────────

def _build_rule_based_fallback(incident_data: dict) -> dict:
    raw_event = incident_data.get("raw_event", {}) or {}
    detection = incident_data.get("detection", {}) or {}
    anomaly = incident_data.get("anomaly_detection", {}) or {}
    ingestion = incident_data.get("ingestion", {}) or {}
    feature_engineering = incident_data.get("feature_engineering", {}) or {}

    # Support both CIS shapes
    cis_direct = incident_data.get("cis", {}) or {}
    cis_benchmark = incident_data.get("cis_benchmark", {}) or {}
    matched_benchmarks = cis_benchmark.get("matched_benchmarks", []) or []

    cis_title = (
        cis_direct.get("title")
        or (matched_benchmarks[0].get("title") if matched_benchmarks else None)
        or "Security Monitoring"
    )

    log_type = str(
        raw_event.get("log_type")
        or ingestion.get("log_family")
        or feature_engineering.get("log_family")
        or "unknown"
    ).lower()

    action = str(
        raw_event.get("action")
        or ingestion.get("action")
        or "suspicious_activity"
    ).lower()

    url = str(raw_event.get("url") or ingestion.get("url_path") or "").strip()
    port = str(raw_event.get("port") or raw_event.get("destination_port") or "").strip()
    protocol = str(raw_event.get("protocol") or "").lower().strip()

    affected_host = str(
        raw_event.get("affected_host")
        or raw_event.get("hostname")
        or ingestion.get("hostname")
        or "unknown asset"
    )

    affected_user = str(raw_event.get("affected_user") or "unknown user")
    source_ip = str(raw_event.get("source_ip") or ingestion.get("source_ip") or "unknown source")
    destination_ip = str(
        raw_event.get("destination_ip")
        or ingestion.get("destination_ip")
        or "unknown destination"
    )

    threat_type = str(detection.get("threat_type") or "suspicious_activity").lower()
    severity = str(detection.get("severity") or "low").lower()
    label = str(detection.get("label") or "suspicious").lower()

    anomaly_flags = anomaly.get("anomaly_flags", []) or []
    if not isinstance(anomaly_flags, list):
        anomaly_flags = [str(anomaly_flags)]

    # Defaults
    intent = "Suspicious Activity"
    summary = f"Suspicious activity was detected from {source_ip} affecting {affected_host}."
    narrative = (
        f"A potentially suspicious event was observed from {source_ip} affecting {affected_host}. "
        f"The event was classified as '{threat_type}' with severity '{severity}'."
    )

    attack_vector = "network"
    attack_complexity = "low"
    privileges_required = "none"
    user_interaction = "none"
    scope = "unchanged"

    confidentiality = "low"
    integrity = "low"
    availability = "low"

    # CVSS impact describes what the attack ACHIEVES, not how alarmed we are.
    # When a branch below sets impact deliberately for its threat class, it marks
    # the values authoritative so the severity refinement at the end leaves them
    # alone. Only the generic default gets nudged by detection severity.
    impact_is_authoritative = False

    # WEB / suspicious request / injection-like behavior
    if log_type == "web" or threat_type in {"web_attack", "suspicious_request"}:
        attack_vector = "network"
        scope = "unchanged"

        url_lower = url.lower()

        # Name the specific payload class when we can see it — an actual
        # injection string is a STRONGER signal than a generic "suspicious
        # request", so these are checked first.
        if "' or '" in url_lower or "or 1=1" in url_lower or "union select" in url_lower or "'1'='1" in url_lower:
            payload_kind = "SQL injection"
            technique = "T1190 (Exploit Public-Facing Application)"
        elif "<script" in url_lower or "javascript:" in url_lower or "onerror=" in url_lower:
            payload_kind = "cross-site scripting"
            technique = "T1059.007 (JavaScript Execution)"
        elif "../" in url_lower or "%2e%2e" in url_lower or "/etc/passwd" in url_lower:
            payload_kind = "path traversal"
            technique = "T1083 (File and Directory Discovery)"
        elif any(x in url_lower for x in (".php", ".jsp", ".asp", "shell", "upload")):
            payload_kind = "webshell / file upload abuse"
            technique = "T1505.003 (Web Shell)"
        else:
            payload_kind = ""
            technique = "T1595 (Active Scanning)"

        if payload_kind or threat_type == "web_attack":
            intent = f"Web Application Attack — {payload_kind}" if payload_kind else "Web Application Attack Attempt"
            summary = (
                f"{payload_kind.capitalize() or 'Web application attack'} attempt from {source_ip} "
                f"targeted {url or 'a protected endpoint'} on {affected_host}."
            )
            narrative = (
                f"A request from {source_ip} to {url or 'a protected endpoint'} on {affected_host} carries "
                f"{('a ' + payload_kind + ' payload') if payload_kind else 'a hostile application-layer pattern'}, "
                f"consistent with {technique}. If the application does not validate this input server-side, the "
                f"attacker could read or alter data they are not authorised to reach — which for a banking "
                f"application means customer records and transaction integrity. "
                f""
            )
            confidentiality = "high"
            integrity = "low"
            availability = "none"
            impact_is_authoritative = True

        else:
            intent = "Suspicious Web Request"
            summary = f"Suspicious web request from {source_ip} targeted {url or 'a web endpoint'}."
            narrative = (
                f"A suspicious request was sent from {source_ip} to {url or 'a web endpoint'}, "
                f"indicating possible probing of application behaviour on {affected_host} "
                f"(consistent with {technique}). No exploit payload was identified in the request itself. "
                f""
            )
            confidentiality = "low"
            integrity = "none"
            availability = "none"
            impact_is_authoritative = True

    # PORT SCAN
    elif threat_type == "port_scan" or action in {"port_scan", "scan"}:
        intent = "Port Scanning / Reconnaissance"
        attack_vector = "network"
        attack_complexity = "low"
        privileges_required = "none"
        user_interaction = "none"
        scope = "unchanged"

        summary = (
            f"Reconnaissance activity from {source_ip} targeted port {port or 'multiple ports'} "
            f"on {destination_ip if destination_ip != 'unknown destination' else affected_host}."
        )
        narrative = (
            f"The source {source_ip} appears to be performing reconnaissance by probing "
            f"{port or 'multiple network ports'} on {destination_ip if destination_ip != 'unknown destination' else affected_host}. "
            f"This behavior is consistent with service discovery prior to exploitation. "
            f""
        )
        confidentiality = "low"
        integrity = "none"
        availability = "none"
        impact_is_authoritative = True

    # BEACONING
    elif threat_type == "beaconing":
        intent = "Command-and-Control Beaconing"
        attack_vector = "network"
        attack_complexity = "low"
        privileges_required = "none"
        user_interaction = "none"
        scope = "unchanged"

        summary = (
            f"Possible beaconing behavior was detected between {source_ip} and "
            f"{destination_ip if destination_ip != 'unknown destination' else affected_host}."
        )
        narrative = (
            f"Repeated or patterned communication suggests possible beaconing activity from {source_ip} "
            f"toward {destination_ip if destination_ip != 'unknown destination' else affected_host}. "
            f"This may indicate malware establishing command-and-control connectivity or maintaining persistence. "
            f""
        )
        confidentiality = "high"
        integrity = "low"
        availability = "none"
        impact_is_authoritative = True

    # LATERAL MOVEMENT
    elif threat_type == "lateral_movement":
        intent = "Internal Lateral Movement"
        attack_vector = "adjacent"
        attack_complexity = "low"
        privileges_required = "low"
        user_interaction = "none"
        scope = "changed"

        target_name = affected_host if affected_host != "unknown asset" else destination_ip
        summary = f"Potential lateral movement from {source_ip} toward {target_name} was detected."
        narrative = (
            f"The event suggests internal movement from {source_ip} toward {target_name}, "
            f"which may indicate an attacker attempting to expand access within the environment. "
            f"If confirmed, this behavior increases the likelihood of privilege abuse and broader compromise. "
            f""
        )
        confidentiality = "high"
        integrity = "high"
        availability = "none"
        impact_is_authoritative = True

    # IOT
    elif log_type == "iot" or threat_type in {"iot_anomaly", "firmware_anomaly", "device_compromise"}:
        intent = "IoT Device Threat Activity"
        attack_vector = "adjacent"
        attack_complexity = "low"
        privileges_required = "none"
        user_interaction = "none"
        scope = "unchanged"

        summary = f"Suspicious IoT activity was detected involving device {affected_host} from source {source_ip}."
        narrative = (
            f"An anomalous IoT-related event was detected involving {affected_host}. "
            f"The activity may reflect device misuse, insecure exposure, or abnormal firmware or communication behavior. "
            f"IoT incidents are important because compromised devices can become entry points into segmented environments. "
            f""
        )
        confidentiality = "high"
        integrity = "low"
        availability = "low"
        impact_is_authoritative = True

    # GENERIC NETWORK
    elif log_type == "network" or threat_type in {"network_anomaly", "network_attack"}:
        intent = "Network Suspicious Activity"
        attack_vector = "network"
        attack_complexity = "low"
        privileges_required = "none"
        user_interaction = "none"
        scope = "unchanged"

        target_name = destination_ip if destination_ip != "unknown destination" else affected_host
        summary = (
            f"Suspicious network activity from {source_ip} to {target_name} "
            f"over {protocol or 'unknown protocol'} was detected."
        )
        narrative = (
            f"A suspicious network event was identified involving source {source_ip} "
            f"and destination {target_name}. "
            f"The behavior may indicate unauthorized access attempts, abnormal communications, or malicious discovery activity. "
            f""
        )
        confidentiality = "low"
        integrity = "low"
        availability = "low"

    # Severity refinement — only for events whose threat class did not set
    # impact deliberately. Escalating a port scan to "high confidentiality
    # impact" just because detection was confident produces indefensible CVSS
    # scores, which is exactly the inconsistency this layer exists to remove.
    if impact_is_authoritative:
        pass
    elif severity == "low":
        pass
    elif severity == "medium":
        confidentiality = "low" if confidentiality == "none" else confidentiality
        integrity = "low" if integrity == "none" else integrity
        availability = "low" if availability == "none" else availability
    elif severity == "high":
        if confidentiality == "low":
            confidentiality = "high"
        if integrity == "low":
            integrity = "high"
        if availability == "none":
            availability = "low"
    elif severity == "critical":
        confidentiality = "high"
        integrity = "high"
        if availability in {"none", "low"}:
            availability = "high"

    allowed_impact = {"none", "low", "high"}
    confidentiality = confidentiality if confidentiality in allowed_impact else "low"
    integrity = integrity if integrity in allowed_impact else "low"
    availability = availability if availability in allowed_impact else "low"

    # The narrative is the one field a non-technical reader will actually read, so
    # it stays prose. Machine detail — raw anomaly flag names, the action verb, the
    # control string — used to be appended to it as sentence fragments, which made
    # the paragraph read like a log line halfway through. Those move to their own
    # field, where the UI can show them under "why we flagged it" and leave the
    # narrative clean.
    if affected_user and affected_user != "unknown user":
        narrative += f" The account {affected_user} was involved."

    signals: list[str] = []
    if anomaly_flags:
        signals.extend(str(flag).replace("_", " ") for flag in anomaly_flags[:4])
    if action and action not in {"suspicious_activity", "unknown"}:
        signals.append(f"observed action: {action.replace('_', ' ')}")

    return {
        "intent": intent,
        "summary": summary,
        "signals": signals,
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "privileges_required": privileges_required,
        "user_interaction": user_interaction,
        "scope": scope,
        "impact": {
            "confidentiality": confidentiality,
            "integrity": integrity,
            "availability": availability
        },
        "narrative": narrative
    }


# ─────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────

def run_ai_analysis(incident_data: dict) -> dict:
    """
    Produce the analysis block for one incident.

    The deterministic analyst is the baseline, not the fallback of last resort —
    it always produces a complete, valid result. An LLM is consulted only when
    one is reachable, and its output is used only if it passes validation. Either
    way the caller gets the same field contract, so Layer 5 never has to care
    which path ran.
    """
    deterministic = _build_rule_based_fallback(incident_data)
    deterministic["source"] = "deterministic"

    if not _is_ollama_available():
        return deterministic

    enriched = llm_analyse(incident_data)
    return enriched or deterministic


def run_layer4(layer3_output: list[dict]) -> list[dict]:
    """
    Parallelized batch processing for AI Analysis.
    Falls back safely to rule-based analysis when LLM is unavailable.
    """
    results = [None] * len(layer3_output)

    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_idx = {
            executor.submit(run_ai_analysis, event): i
            for i, event in enumerate(layer3_output)
        }

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            event_copy = layer3_output[idx].copy()
            try:
                event_copy["ai_analysis"] = future.result()
            except Exception:
                fallback = _build_rule_based_fallback(layer3_output[idx])
                fallback["source"] = "deterministic"
                event_copy["ai_analysis"] = fallback
            results[idx] = event_copy

    return results