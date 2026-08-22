from .correlation_utils import append_unique, safe_float


def collect_signals(event: dict) -> dict:
    anomaly = event.get("anomaly_detection", {}) or {}
    threat = event.get("threat_analysis", {}) or {}
    ioc = event.get("ioc_enrichment", {}) or {}

    supporting_signals: list[str] = []
    reasons: list[str] = []

    anomaly_score = safe_float(anomaly.get("anomaly_score"), 0.0)
    anomaly_level = anomaly.get("anomaly_level", "none")
    threat_type = threat.get("mapped_pattern", "unknown")
    threat_confidence = safe_float(threat.get("confidence"), 0.0)
    ioc_matched = bool(ioc.get("matched", False))
    ioc_risk = ioc.get("risk_level", "low")

    if anomaly_score >= 0.5:
        append_unique(supporting_signals, "anomaly_detected")
        reasons.append(f"Anomaly engine reported score {anomaly_score}")

    if anomaly_level in {"medium", "high"}:
        append_unique(supporting_signals, "meaningful_anomaly_level")

    if threat_type != "unknown":
        append_unique(supporting_signals, "threat_pattern_identified")
        reasons.append(f"Threat analysis mapped event to {threat_type}")

    if threat_confidence >= 0.5:
        append_unique(supporting_signals, "high_threat_confidence")

    if ioc_matched:
        append_unique(supporting_signals, "ioc_match_found")
        reasons.append("IOC enrichment found matching indicators")

    if ioc_risk in {"medium", "high"}:
        append_unique(supporting_signals, "elevated_ioc_risk")

    return {
        "supporting_signals": supporting_signals,
        "reasons": reasons,
        "anomaly_score": anomaly_score,
        "threat_confidence": threat_confidence,
        "ioc_matched": ioc_matched,
        "ioc_risk": ioc_risk,
        "threat_type": threat_type,
    }
