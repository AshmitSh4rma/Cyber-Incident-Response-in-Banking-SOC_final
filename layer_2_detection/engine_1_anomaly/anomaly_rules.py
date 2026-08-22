import soc_config

from .anomaly_utils import append_flag, append_reason, as_bool, safe_float


def evaluate_anomaly_rules(event: dict) -> dict:
    """
    Reads Layer 1 features and produces anomaly flags + reasons.
    """
    temporal = event.get("temporal_features", {}) or {}
    behavioral = event.get("behavioral_features", {}) or {}
    statistical = event.get("statistical_features", {}) or {}
    network = event.get("network_features", {}) or {}
    identity = event.get("identity_features", {}) or {}

    flags: list[str] = []
    reasons: list[str] = []

    # Temporal
    if as_bool(temporal.get("is_off_hours")):
        append_flag(flags, "off_hours_activity")
        append_reason(reasons, "Activity observed during off-hours")

    # Behavioral
    failed_login_count = safe_float(behavioral.get("failed_login_count"), 0)
    if failed_login_count >= soc_config.get_int("detection.brute_force_attempts"):
        append_flag(flags, "login_failure_spike")
        append_reason(reasons, f"Failed login count is high ({int(failed_login_count)})")

    if as_bool(behavioral.get("rare_source_ip")):
        append_flag(flags, "rare_source_ip")
        append_reason(reasons, "Source IP appears unusual for this activity")

    if as_bool(behavioral.get("rare_user_activity")):
        append_flag(flags, "rare_user_activity")
        append_reason(reasons, "User behavior appears unusual")

    # Statistical
    z_score = safe_float(statistical.get("z_score"), 0)
    if z_score >= 2.5:
        append_flag(flags, "high_z_score")
        append_reason(reasons, f"Statistical deviation is high (z_score={z_score})")

    event_count_window = safe_float(statistical.get("event_count_window"), 0)
    if event_count_window >= 10:
        append_flag(flags, "event_volume_spike")
        append_reason(reasons, f"Event volume spike detected ({int(event_count_window)} events in window)")

    # Network
    if as_bool(network.get("suspicious_port")):
        append_flag(flags, "suspicious_port")
        append_reason(reasons, "Connection uses a suspicious or uncommon port")

    # There is deliberately no "sensitive path" flag. The only Layer 1 field that
    # could feed one, web_http_features.is_suspicious_path, matches 32 substrings
    # including "api", "v1", "login" and "auth" — so it fires on very nearly every
    # request a bank serves. A flag that is always raised carries no information;
    # it would just add a constant to every web event's anomaly score and move
    # the meaning of every threshold compared against it.

    # Identity
    if as_bool(identity.get("risky_signin")):
        append_flag(flags, "risky_signin")
        append_reason(reasons, "Identity/risk engine flagged sign-in as risky")

    return {
        "flags": flags,
        "reasoning": reasons
    }
