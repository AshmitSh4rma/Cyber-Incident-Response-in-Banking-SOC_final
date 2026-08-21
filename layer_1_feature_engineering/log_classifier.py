# log_classifier.py
# Location: layer_1_feature_engineering/log_classifier.py
#
# PURPOSE:
# Reads the normalized log dict arriving from the ingestion layer
# and determines which family it belongs to — network, web, or iot.
#
# HOW IT WORKS:
# Each field in the log is checked against a signature map.
# Strong fields = 2 points, Weak fields = 1 point.
# The family with the highest score wins.
# If there is a tie, defaults to "network" as it is the most common log type.
# If no fields match at all, returns "unknown".
#
# CALLED BY:
# feature_orchestrator.py — first thing it does before routing to any engine


# ─────────────────────────────────────────
# SIGNATURE MAP
# Each family has strong fields (2 pts) and weak fields (1 pt)
# These are fields that ONLY that log type will have
# ─────────────────────────────────────────

SIGNATURE_MAP = {
    "network": {
        "strong": ["bytes_in", "bytes_out", "packets", "tcp_flags", "icmp_type"],
        "weak":   ["protocol", "src_port", "dest_port", "duration_ms"]
    },
    "web": {
        "strong": ["http_method", "http_status_code", "url_path", "response_size"],
        "weak":   ["user_agent", "referrer", "session_id", "content_type"]
    },
    "iot": {
        "strong": ["device_id", "firmware_version", "mqtt_topic", "sensor_reading"],
        "weak":   ["device_type", "sampling_interval", "telemetry_value", "battery_level"]
    }
}


# ─────────────────────────────────────────
# DECLARED TYPE MAP
# Many collectors state the log type outright (log_type / event_source).
# When they do, that beats guessing from field presence — so we trust it and
# only fall back to signature scoring when the declared type is absent or
# names something we have no engine for.
#
# auth and endpoint telemetry has no dedicated Layer 1 engine, so it routes to
# the network engine (it is host-to-host traffic at heart) while the identity
# engine picks up the credential side separately.
# ─────────────────────────────────────────

DECLARED_FAMILY_MAP = {
    "network":  "network",
    "netflow":  "network",
    "firewall": "network",
    "ids":      "network",
    "ips":      "network",
    "dns":      "network",
    "auth":     "network",
    "identity": "network",
    "endpoint": "network",
    "process":  "network",
    "host":     "network",
    "web":      "web",
    "http":     "web",
    "https":    "web",
    "waf":      "web",
    "proxy":    "web",
    "apache":   "web",
    "nginx":    "web",
    "iot":      "iot",
    "ot":       "iot",
    "scada":    "iot",
    "mqtt":     "iot",
}


def _declared_family(log: dict) -> tuple[str | None, str | None]:
    """
    Returns (declared_type, mapped_family). Either may be None.
    Looks at the normalized log_type first, then the raw record, so it works
    whether or not ingestion carried the field through.
    """
    raw_event = log.get("raw_event") or {}
    additional = log.get("additional_fields") or {}

    for candidate in (
        log.get("log_type"),
        raw_event.get("log_type"),
        additional.get("log_type"),
        log.get("event_source"),
        raw_event.get("event_source"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            declared = candidate.strip().lower()
            return declared, DECLARED_FAMILY_MAP.get(declared)

    return None, None


# ─────────────────────────────────────────
# SCORER
# Iterates over each family's fields and tallies the score
# ─────────────────────────────────────────

def _has_signal(value) -> bool:
    """
    Returns True only for meaningful values.
    Rejects:
    - None
    - 0
    - empty string
    - empty list/dict/set/tuple
    """
    if value is None:
        return False
    if value == 0:
        return False
    if isinstance(value, str) and value.strip() == "":
        return False
    if isinstance(value, (list, dict, set, tuple)) and len(value) == 0:
        return False
    return True


def _score_log(log: dict) -> dict[str, int]:
    """
    Returns a score dict like:
    {"network": 3, "web": 0, "iot": 0}
    """
    scores = {"network": 0, "web": 0, "iot": 0}

    for family, field_groups in SIGNATURE_MAP.items():
        for field in field_groups["strong"]:
            value = log.get(field)
            if _has_signal(value):
                scores[family] += 2

        for field in field_groups["weak"]:
            value = log.get(field)
            if _has_signal(value):
                scores[family] += 1

    return scores


# ─────────────────────────────────────────
# CLASSIFIER
# Main function called by the orchestrator
# ─────────────────────────────────────────

def classify_log(log: dict) -> dict:
    """
    Receives the normalized log dict.
    Stamps it with log_family and classification_scores.
    Returns the enriched dict — never modifies in place.

    Added fields:
        log_family           : "network" | "web" | "iot" | "unknown"
        classification_scores: {"network": int, "web": int, "iot": int}
        classification_confidence: "high" | "medium" | "low"
    """

    scores = _score_log(log)
    total_score = sum(scores.values())

    declared_type, declared_family = _declared_family(log)

    # The collector told us what this is and we have an engine for it — trust it.
    if declared_family:
        return {
            **log,
            "log_family": declared_family,
            "declared_log_type": declared_type,
            "classification_scores": scores,
            "classification_confidence": "high",
            "classification_basis": "declared_log_type",
        }

    # If nothing matched at all
    if total_score == 0:
        return {
            **log,
            "log_family": "unknown",
            "declared_log_type": declared_type,
            "classification_scores": scores,
            "classification_confidence": "low",
            "classification_basis": "no_signal",
        }

    # Find the winning family
    max_score = max(scores.values())
    winners = [family for family, score in scores.items() if score == max_score]

    # Resolve tie — default to network
    if len(winners) > 1:
        winning_family = "network"
        confidence = "low"

    else:
        winning_family = winners[0]

        # Confidence based on how dominant the winner is
        runner_up = sorted(scores.values(), reverse=True)[1]
        gap = max_score - runner_up

        if gap >= 4:
            confidence = "high"
        elif gap >= 2:
            confidence = "medium"
        else:
            confidence = "low"

    return {
        **log,
        "log_family": winning_family,
        "declared_log_type": declared_type,
        "classification_scores": scores,
        "classification_confidence": confidence,
        "classification_basis": "field_signature",
    }