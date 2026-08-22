def get_severity(base_score: float) -> str:
    """
    Translates numerical scores (0.0 - 10.0) into standardized string severity.
    """
    if base_score == 0.0:
        return "none"
    if 0.1 <= base_score <= 3.9:
        return "low"
    if 4.0 <= base_score <= 6.9:
        return "medium"
    if 7.0 <= base_score <= 8.9:
        return "high"
    if 9.0 <= base_score <= 10.0:
        return "critical"
    return "unknown"
