def map_reputation(matches: list[dict]) -> dict:
    if not matches:
        return {
            "matched": False,
            "risk_level": "low",
            "match_count": 0,
            "matched_iocs": []
        }

    highest_confidence = max(float(match.get("confidence", 0.0)) for match in matches)

    if highest_confidence >= 0.85:
        risk_level = "high"
    elif highest_confidence >= 0.6:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "matched": True,
        "risk_level": risk_level,
        "match_count": len(matches),
        "matched_iocs": matches
    }
