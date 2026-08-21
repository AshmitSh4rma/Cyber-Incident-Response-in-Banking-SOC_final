# Most severe / most specific first. The first pattern in this list that the
# mapper matched becomes the event's headline threat type.
PATTERN_PRIORITY = [
    "malware_execution",
    "data_exfiltration",
    "lateral_movement",
    "privilege_escalation",
    "beaconing",
    "brute_force_attempt",
    "credential_abuse",
    "web_attack",
    "suspicious_command_execution",
    "risky_signin_detected",
    "suspicious_login_behavior",
    "insecure_protocol_use",
    "port_scan",
    "suspicious_web_access",
    "anomalous_activity",
]

SEVERITY_MAP = {
    "malware_execution":            "critical",
    "data_exfiltration":            "critical",
    "lateral_movement":             "critical",
    "privilege_escalation":         "high",
    "beaconing":                    "high",
    "brute_force_attempt":          "high",
    "credential_abuse":             "high",
    "web_attack":                   "high",
    "suspicious_command_execution": "high",
    "risky_signin_detected":        "high",
    "suspicious_login_behavior":    "medium",
    "insecure_protocol_use":        "medium",
    "port_scan":                    "medium",
    "suspicious_web_access":        "medium",
    "anomalous_activity":           "medium",
}


def classify_threat(mapped: dict) -> dict:
    patterns = mapped.get("matched_patterns", [])
    reasons = mapped.get("reasoning", [])

    if not patterns:
        return {
            "threat_type": "unknown",
            "severity": "low",
            "confidence": 0.0,
            "reasoning": reasons
        }

    selected = None
    for p in PATTERN_PRIORITY:
        if p in patterns:
            selected = p
            break

    if not selected:
        selected = patterns[0]

    severity = SEVERITY_MAP.get(selected, "medium")

    # Base confidence on the severity of the selected pattern, then add a small
    # bump for each corroborating pattern. A single high-severity signature is
    # more trustworthy than several weak ones.
    base_by_severity = {"critical": 0.80, "high": 0.72, "medium": 0.58, "low": 0.45}
    confidence = min(0.97, base_by_severity.get(severity, 0.55) + 0.06 * (len(patterns) - 1))

    reasons.append(f"Classified as {selected}")

    return {
        "threat_type": selected,
        "severity": severity,
        "confidence": round(confidence, 2),
        "reasoning": reasons
    }