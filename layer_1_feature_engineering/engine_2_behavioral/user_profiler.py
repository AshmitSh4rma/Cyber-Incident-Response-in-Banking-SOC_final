# user_profiler.py
#
# PURPOSE:
# Builds a behavioral snapshot of the current user/entity
# from the incoming log.
# Tracks what this user is doing RIGHT NOW.
#
# WHAT IT PRODUCES:
# A profile snapshot — current behavior data points that the
# baseline_comparator will compare against stored history.
#
# IN-MEMORY STORE:
# Maintains a per-user history of recent actions, IPs, hours.
# Same design as tsfresh_extractor's event store.
#
# CALLED BY:
# behavioral_orchestrator.py


from collections import defaultdict
from datetime import UTC, datetime

# ─────────────────────────────────────────
# IN-MEMORY USER STORE
# Key: username or source_ip if no user
# Value: dict of behavioral history
# ─────────────────────────────────────────

_user_store: dict[str, dict] = defaultdict(lambda: {
    "seen_ips":         set(),
    "seen_hours":       set(),
    "action_counts":    defaultdict(int),
    "event_counts":     defaultdict(int),
    "total_events":     0,
    "failed_logins":    0,
    "last_seen":        None
})

MAX_IPS_PER_USER = 50


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(UTC)


def _get_user_key(log: dict) -> str:
    """
    Returns the key to identify this user/entity.
    Prefers username, falls back to source_ip.
    """
    return log.get("user") or log.get("source_ip", "unknown")


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def build_user_profile(log: dict) -> dict:
    """
    Reads the log, updates the user store,
    and returns the log with a user_profile block added.

    Added block:
    {
        "user_profile": {
            "user_key":             "jsmith",
            "is_new_user":          False,
            "current_hour":         2,
            "current_source_ip":    "192.168.1.105",
            "is_new_ip_for_user":   True,
            "total_events_seen":    47,
            "failed_login_count":   3,
            "unique_ips_seen":      4,
            "current_action":       "deny",
            "current_event_type":   "connection_attempt"
        }
    }
    """

    user_key   = _get_user_key(log)
    source_ip  = log.get("source_ip", "unknown")
    timestamp  = log.get("timestamp", "")
    action     = log.get("action", "unknown")
    event_type = log.get("event_type", "unknown")

    dt   = _parse_ts(timestamp)
    hour = dt.hour

    profile = _user_store[user_key]

    # ── Is this a new user ──
    is_new_user = profile["total_events"] == 0

    # ── Is this a new IP for this user ──
    is_new_ip = source_ip not in profile["seen_ips"]

    # ── Update the store ──
    profile["seen_ips"].add(source_ip)
    profile["seen_hours"].add(hour)
    profile["action_counts"][action] += 1
    profile["event_counts"][event_type] += 1
    profile["total_events"] += 1
    profile["last_seen"] = timestamp

    # Track failed logins specifically
    if "fail" in action.lower() or "deny" in action.lower():
        profile["failed_logins"] += 1

    # Trim IPs if too many
    if len(profile["seen_ips"]) > MAX_IPS_PER_USER:
        profile["seen_ips"] = set(list(profile["seen_ips"])[-MAX_IPS_PER_USER:])

    user_profile = {
        "user_key":           user_key,
        "is_new_user":        is_new_user,
        "current_hour":       hour,
        "current_source_ip":  source_ip,
        "is_new_ip_for_user": is_new_ip,
        "total_events_seen":  profile["total_events"],
        "failed_login_count": profile["failed_logins"],
        "unique_ips_seen":    len(profile["seen_ips"]),
        "current_action":     action,
        "current_event_type": event_type
    }

    return {**log, "user_profile": user_profile}
