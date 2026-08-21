from .correlation_utils import safe_float


def adjust_confidence(event: dict, matched_result: dict) -> dict:
    anomaly_score = safe_float(event.get("anomaly_detection", {}).get("anomaly_score"), 0.0)
    threat_confidence = safe_float(event.get("threat_analysis", {}).get("confidence"), 0.0)

    ioc_block = event.get("ioc_enrichment", {}) or {}
    ioc_matched = bool(ioc_block.get("matched", False))
    ioc_risk = ioc_block.get("risk_level", "low")

    correlation_strength = matched_result.get("correlation_strength", "none")

    base_confidence = max(anomaly_score, threat_confidence)

    # Corroborating evidence should move confidence toward certainty without ever
    # reaching it. Bonuses are applied against the REMAINING headroom rather than
    # added outright, so stacking signals converges instead of saturating — a
    # detection that claims 0.99 confidence on three weak signals is not credible.
    bonus = 0.0

    if ioc_matched:
        if ioc_risk == "high":
            bonus += 0.45
        elif ioc_risk == "medium":
            bonus += 0.25
        else:
            bonus += 0.12

    if correlation_strength == "strong":
        bonus += 0.35
    elif correlation_strength == "medium":
        bonus += 0.18
    elif correlation_strength == "weak":
        bonus += 0.07

    bonus = min(bonus, 0.80)
    adjusted = base_confidence + (1.0 - base_confidence) * bonus

    # 0.95 is the practical ceiling: rule-based detection does not get to claim
    # near-certainty, and analysts need to see the difference between a 0.78 and
    # a 0.93 to triage in the right order.
    adjusted_confidence = min(round(adjusted, 2), 0.95)

    return {
        "adjusted_confidence": adjusted_confidence
    }