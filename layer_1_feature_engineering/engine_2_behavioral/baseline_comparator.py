# baseline_comparator.py
#
# PURPOSE:
# Compares the current user profile snapshot against
# their established behavioral baseline.
# Produces a deviation score and specific deviation flags.
#
# WHY THIS MATTERS:
# A login at 2AM is normal for a night shift worker.
# The same login is suspicious for a 9-5 office employee.
# Context-aware comparison is what makes UEBA meaningful.
#
# HOW BASELINE WORKS:
# The baseline is built from the user's own history in the store.
# It is not a static rule — it adapts as more events are seen.
# New users get a neutral baseline with moderate deviation scores
# until enough history is accumulated.
#
# CALLED BY:
# behavioral_orchestrator.py


from collections import defaultdict

import soc_config

# ─────────────────────────────────────────
# BASELINE STORE
# Key: user_key
# Value: dict of baseline behavioral norms
# Built incrementally from user_profiler's store
# ─────────────────────────────────────────

_baseline_store: dict[str, dict] = defaultdict(lambda: {
    "normal_hours":         set(),
    "normal_ips":           set(),
    "avg_events_per_hour":  0,
    "avg_failed_logins":    0,
    "baseline_established": False
})

# Minimum events before baseline is considered reliable
BASELINE_MIN_EVENTS = 10


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _update_baseline(user_key: str, user_profile: dict) -> None:
    """
    Updates the baseline store for this user
    based on their latest profile snapshot.
    Baseline grows with each event seen.
    """
    baseline = _baseline_store[user_key]

    # Add current hour to normal hours
    baseline["normal_hours"].add(user_profile["current_hour"])

    # Add current IP to normal IPs
    baseline["normal_ips"].add(user_profile["current_source_ip"])

    # Update average events
    total = user_profile["total_events_seen"]
    if total >= BASELINE_MIN_EVENTS:
        baseline["baseline_established"] = True

    # Rolling average failed logins
    baseline["avg_failed_logins"] = (
        (baseline["avg_failed_logins"] + user_profile["failed_login_count"]) / 2
    )


def _calculate_deviation_score(flags: dict) -> float:
    """
    Converts deviation flags into a single score between 0.0 and 1.0.
    Each flag contributes a weighted amount.
    Score represents how anomalous this behavior is.
    """
    weights = {
        "is_off_hours_for_user":      0.25,
        "is_new_ip_for_user":         0.20,
        "is_new_user":                0.15,
        "excessive_failed_logins":    0.25,
        "baseline_not_established":   0.15
    }

    score = 0.0
    for flag, weight in weights.items():
        if flags.get(flag, False):
            score += weight

    return round(min(score, 1.0), 3)


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def compare_to_baseline(log: dict) -> dict:
    """
    Reads the user_profile block added by user_profiler.
    Compares it against the stored baseline for this user.
    Returns the log with behavioral_features block added.

    Added block:
    {
        "behavioral_features": {
            "deviation_score":          0.45,
            "is_off_hours_for_user":    True,
            "is_new_ip_for_user":       True,
            "is_new_user":              False,
            "excessive_failed_logins":  False,
            "baseline_established":     True,
            "normal_hours_count":       8,
            "normal_ips_count":         3
        }
    }
    """

    user_profile = log.get("user_profile", {})
    user_key     = user_profile.get("user_key", "unknown")
    baseline     = _baseline_store[user_key]

    # ── Update baseline with current profile ──
    _update_baseline(user_key, user_profile)

    # ── Compute deviation flags ──
    current_hour = user_profile.get("current_hour", 0)

    is_off_hours_for_user = (
        len(baseline["normal_hours"]) > 0 and
        current_hour not in baseline["normal_hours"]
    )

    is_new_ip = user_profile.get("is_new_ip_for_user", False)
    is_new_user = user_profile.get("is_new_user", False)

    excessive_failed = (
        user_profile.get("failed_login_count", 0)
        >= soc_config.get_int("detection.brute_force_attempts")
    )

    baseline_not_established = not baseline["baseline_established"]

    flags = {
        "is_off_hours_for_user":    is_off_hours_for_user,
        "is_new_ip_for_user":       is_new_ip,
        "is_new_user":              is_new_user,
        "excessive_failed_logins":  excessive_failed,
        "baseline_not_established": baseline_not_established
    }

    deviation_score = _calculate_deviation_score(flags)

    behavioral_features = {
        "deviation_score":         deviation_score,
        "is_off_hours_for_user":   is_off_hours_for_user,
        "is_new_ip_for_user":      is_new_ip,
        "is_new_user":             is_new_user,
        "excessive_failed_logins": excessive_failed,
        "baseline_established":    baseline["baseline_established"],
        "normal_hours_count":      len(baseline["normal_hours"]),
        "normal_ips_count":        len(baseline["normal_ips"])
    }

    return {**log, "behavioral_features": behavioral_features}
