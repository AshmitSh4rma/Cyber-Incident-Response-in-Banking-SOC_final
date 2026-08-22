from .anomaly_utils import safe_float

FLAG_WEIGHTS = {
    "off_hours_activity": 0.10,
    "login_failure_spike": 0.25,
    "rare_source_ip": 0.15,
    "rare_user_activity": 0.15,
    "high_z_score": 0.20,
    "event_volume_spike": 0.20,
    "suspicious_port": 0.15,
    "risky_signin": 0.20,
}


def compute_anomaly_score(rule_result: dict, event: dict) -> dict:
    flags = rule_result.get("flags", []) or []
    reasons = rule_result.get("reasoning", []) or []

    score = 0.0

    for flag in flags:
        score += FLAG_WEIGHTS.get(flag, 0.05)

    # small boost from existing statistical signal if present
    statistical = event.get("statistical_features", {}) or {}
    z_score = safe_float(statistical.get("z_score"), 0)
    if z_score >= 3:
        score += 0.10

    score = min(score, 0.99)

    if score >= 0.85:
        label = "high"
    elif score >= 0.50:
        label = "medium"
    elif score > 0:
        label = "low"
    else:
        label = "none"

    return {
        "anomaly_score": round(score, 2),
        "anomaly_level": label,
        "anomaly_flags": flags,
        "reasoning": reasons
    }
