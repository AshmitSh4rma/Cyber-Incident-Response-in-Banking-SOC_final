def fuse_detection(event: dict) -> dict:
    anomaly = event.get("anomaly_detection", {}) or {}
    threat = event.get("threat_analysis", {}) or {}
    ioc = event.get("ioc_enrichment", {}) or {}
    correlation = event.get("correlation_analysis", {}) or {}

    anomaly_score = float(anomaly.get("anomaly_score", 0.0))
    threat_type = str(threat.get("mapped_pattern", "unknown")).lower()
    threat_severity = str(threat.get("severity", "low")).lower()
    ioc_matched = bool(ioc.get("matched", False))
    ioc_risk = str(ioc.get("risk_level", "low")).lower()
    adjusted_confidence = float(correlation.get("adjusted_confidence", 0.0))
    correlation_strength = str(correlation.get("correlation_strength", "none")).lower()

    triggered_engines = []
    reasoning = []

    if anomaly_score > 0:
        triggered_engines.append("anomaly")
        reasoning.extend(anomaly.get("reasoning", []))

    if threat_type != "unknown":
        triggered_engines.append("threat_analysis")
        reasoning.extend(threat.get("reasoning", []))

    if ioc_matched:
        triggered_engines.append("ioc_enrichment")
        reasoning.append("IOC enrichment contributed supporting threat context")

    if correlation_strength != "none":
        triggered_engines.append("correlation")
        reasoning.extend(correlation.get("reasoning", []))

    # ----------------------------
    # Final label
    # ----------------------------
    # Precision matters more than recall here. The anomaly engine returns a small
    # non-zero score for almost every event (an unfamiliar source IP alone earns
    # 0.3), so "anomaly_score > 0" as a trigger labels ordinary traffic
    # suspicious and buries the real findings. Require either a NAMED threat
    # pattern or a genuinely high anomaly score.
    if adjusted_confidence >= 0.85 and threat_type != "unknown":
        label = "malicious"
    elif threat_type != "unknown" and adjusted_confidence >= 0.35:
        label = "suspicious"
    elif anomaly_score >= 0.60:
        # Nothing matched a signature, but the behaviour itself is a clear outlier.
        label = "suspicious"
    else:
        label = "benign"

    # ----------------------------
    # Final severity
    # ----------------------------
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def raise_severity(current: str, new_level: str) -> str:
        if severity_rank.get(new_level, 1) > severity_rank.get(current, 1):
            return new_level
        return current

    final_severity = threat_severity if threat_severity in severity_rank else "low"

    # 1. Threat-type based severity
    if threat_type in {"suspicious_request", "web_probe", "network_anomaly"}:
        final_severity = raise_severity(final_severity, "low")

    elif threat_type in {"port_scan", "iot_anomaly", "firmware_anomaly"}:
        final_severity = raise_severity(final_severity, "medium")

    elif threat_type in {"web_attack", "credential_abuse", "beaconing", "device_compromise"}:
        final_severity = raise_severity(final_severity, "high")

    elif threat_type in {"lateral_movement", "endpoint_compromise", "malware_execution"}:
        final_severity = raise_severity(final_severity, "critical")

    # 2. IOC-based severity raise
    if ioc_risk == "high":
        final_severity = raise_severity(final_severity, "high")
    elif ioc_risk == "medium":
        final_severity = raise_severity(final_severity, "medium")

    # 3. Anomaly-score based raise
    if anomaly_score >= 0.90:
        final_severity = raise_severity(final_severity, "high")
    elif anomaly_score >= 0.70:
        final_severity = raise_severity(final_severity, "medium")

    # 4. Correlation-confidence based raise
    # Confidence says how SURE we are, not how BAD it is. High confidence in a
    # port scan is still a port scan, so confidence alone caps out at "high" —
    # only the threat class itself (rule 1) or a malicious verdict on a
    # critical-class threat can reach "critical".
    if adjusted_confidence >= 0.75:
        final_severity = raise_severity(final_severity, "high")
    elif adjusted_confidence >= 0.50:
        final_severity = raise_severity(final_severity, "medium")

    # 5. Correlation-strength raise
    if correlation_strength == "strong":
        final_severity = raise_severity(final_severity, "high")
    elif correlation_strength == "medium":
        final_severity = raise_severity(final_severity, "medium")

    # 6. Label floor. Benign events keep low severity — flooring them to medium
    # is what turns a clean queue into 46% false positives.
    if label == "malicious":
        final_severity = raise_severity(final_severity, "high")
    elif label == "suspicious":
        final_severity = raise_severity(final_severity, "medium")
    else:
        final_severity = "low"

    # remove duplicate reasoning while preserving order
    deduped_reasoning = []
    seen = set()
    for item in reasoning:
        if item not in seen:
            seen.add(item)
            deduped_reasoning.append(item)

    event["detection"] = {
        "label": label,
        "threat_type": threat_type,
        "severity": final_severity,
        "confidence": round(adjusted_confidence, 2),
        "triggered_engines": triggered_engines,
        "reasoning": deduped_reasoning,
    }

    return event