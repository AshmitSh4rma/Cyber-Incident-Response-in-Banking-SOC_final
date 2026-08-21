def adapt_layer1_event(event: dict) -> dict:
    adapted = dict(event)

    source = event.get("source", {}) or {}
    destination = event.get("destination", {}) or {}
    raw_event = event.get("raw_event", {}) or {}
    ecs_event = event.get("event", {}) or {}
    time_windows = event.get("time_windows", {}) or {}
    user_profile = event.get("user_profile", {}) or {}
    frequency = event.get("frequency_features", {}) or {}
    pattern = event.get("pattern_features", {}) or {}
    identity = event.get("identity_features", {}) or {}

    adapted["source_ip"] = (
        event.get("source_ip")
        or source.get("ip")
        or event.get("IpAddress")
        or event.get("ClientIP")
        or "unknown"
    )

    adapted["destination_ip"] = (
        event.get("destination_ip")
        or destination.get("ip")
        or ""
    )

    adapted["action"] = (
        event.get("action")
        or raw_event.get("action")
        or ecs_event.get("action")
        or ""
    )

    # Layer 1 normalises the request path to url_path; Layer 2's pattern rules
    # look for `url`. Bridge it so web payload signatures actually get evaluated.
    adapted["url"] = (
        event.get("url")
        or event.get("url_path")
        or raw_event.get("url")
        or raw_event.get("url_path")
        or ""
    )

    # Carry the declared log type through so pattern rules gated on it can fire.
    adapted["log_type"] = (
        event.get("log_type")
        or raw_event.get("log_type")
        or event.get("log_family")
        or ""
    )

    temporal = dict(event.get("temporal_features", {}) or {})
    temporal["is_off_hours"] = time_windows.get("is_off_hours", False)
    adapted["temporal_features"] = temporal

    behavioral = dict(event.get("behavioral_features", {}) or {})
    behavioral["failed_login_count"] = (
        behavioral.get("failed_login_count")
        or user_profile.get("failed_login_count")
        or pattern.get("failed_login_count")
        or 0
    )
    behavioral["rare_source_ip"] = (
        behavioral.get("rare_source_ip")
        or behavioral.get("is_new_ip_for_user")
        or False
    )
    behavioral["rare_user_activity"] = (
        behavioral.get("rare_user_activity")
        or behavioral.get("is_new_user")
        or False
    )
    behavioral["login_failure_spike"] = (
        behavioral.get("login_failure_spike")
        or behavioral.get("excessive_failed_logins")
        or pattern.get("brute_force_detected")
        or False
    )
    adapted["behavioral_features"] = behavioral

    statistical = dict(event.get("statistical_features", {}) or {})
    statistical["z_score"] = (
        statistical.get("z_score")
        or frequency.get("zscore")
        or 0.0
    )
    statistical["event_count_window"] = (
        statistical.get("event_count_window")
        or frequency.get("current_window_count")
        or 0
    )
    adapted["statistical_features"] = statistical

    identity_features = dict(identity)
    identity_features["risky_signin"] = (
        identity.get("risky_signin")
        or identity.get("is_risky_signin")
        or False
    )
    adapted["identity_features"] = identity_features

    return adapted