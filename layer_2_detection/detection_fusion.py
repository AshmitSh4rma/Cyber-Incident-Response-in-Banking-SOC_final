def fuse_detection(event: dict) -> dict:
    anomaly = event.get("anomaly_detection", {}) or {}
    threat = event.get("threat_analysis", {}) or {}
    ioc = event.get("ioc_enrichment", {}) or {}
    correlation = event.get("correlation_analysis", {}) or {}

    anomaly_score = float(anomaly.get("anomaly_score", 0.0))
    threat_type = str(threat.get("mapped_pattern", "unknown")).lower()
    ioc_matched = bool(ioc.get("matched", False))
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
    # Severity answers ONE question: what could this class of activity achieve?
    # It is therefore a pure function of the threat type, and nothing else moves it.
    #
    # Confidence, threat-intel matches and correlation strength deliberately do NOT
    # raise it. They answer a different question — how sure are we this is
    # happening — and conflating the two produced the same behaviour at two
    # different severities: two identical port scans came out `medium` and `high`
    # purely because one source also appeared in the indicator feed. That makes the
    # queue impossible to sort honestly and inflated the high-severity count to 14
    # of 25.
    #
    # Corroboration still surfaces, in the two places it belongs: it drives the
    # LABEL above (benign -> suspicious -> malicious) and it is reported as
    # `confidence`. An analyst sorts by severity to decide what matters and reads
    # confidence to decide how much to trust it. Those have to stay separable.
    SEVERITY_BY_THREAT = {
        # Pre-compromise: information gathering, nothing achieved yet.
        "suspicious_request": "low",
        "web_probe": "low",
        "network_anomaly": "low",
        "suspicious_web_access": "medium",
        "port_scan": "medium",
        "iot_anomaly": "medium",
        "firmware_anomaly": "medium",
        "insecure_protocol_use": "medium",
        "suspicious_login_behavior": "medium",
        # Access achieved, or credentials in play.
        "web_attack": "high",
        "credential_abuse": "high",
        "brute_force_attempt": "high",
        "beaconing": "high",
        "device_compromise": "high",
        "risky_signin_detected": "high",
        "suspicious_command_execution": "high",
        "privilege_escalation": "high",
        # Hands on keyboard inside the network, or data/systems affected.
        "lateral_movement": "critical",
        "endpoint_compromise": "critical",
        "malware_execution": "critical",
        "data_exfiltration": "critical",
    }

    final_severity = SEVERITY_BY_THREAT.get(threat_type, "low")

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
