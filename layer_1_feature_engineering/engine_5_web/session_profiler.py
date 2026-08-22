# session_profiler.py
#
# PURPOSE:
# Profiles the web session for consistency and anomalies.
# Tracks session behavior across requests — user agent
# consistency, referrer patterns, session duration,
# and geographic/source consistency.
#
# WHY THIS MATTERS:
# Session hijacking and credential stuffing attacks often
# show inconsistent session behavior — same session ID
# from two different IPs, sudden user agent change mid-session,
# requests with no referrer hitting deep URLs directly.
#
# CALLED BY:
# web_orchestrator.py


from collections import defaultdict
from datetime import UTC, datetime

# ─────────────────────────────────────────
# IN-MEMORY SESSION STORE
# Key: session_id or source_ip if no session
# Value: session history
# ─────────────────────────────────────────

_session_store: dict[str, dict] = defaultdict(lambda: {
    "seen_ips":          set(),
    "seen_user_agents":  set(),
    "seen_referrers":    set(),
    "request_count":     0,
    "first_seen":        None,
    "last_seen":         None,
    "url_paths":         []
})

MAX_PATHS = 50


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _get_session_key(log: dict) -> str:
    """
    Returns session identifier.
    Prefers session_id, falls back to source_ip.
    """
    return log.get("session_id") or log.get("source_ip", "unknown")


def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(UTC)


def _get_session_duration_seconds(first: str, last: str) -> float:
    """Returns session duration in seconds between first and last seen."""
    if not first or not last:
        return 0.0
    try:
        dt_first = _parse_ts(first)
        dt_last  = _parse_ts(last)
        return abs((dt_last - dt_first).total_seconds())
    except Exception:
        return 0.0


def _is_direct_deep_access(url_path: str, referrer: str) -> bool:
    """
    Returns True if a deep URL (depth > 2) was accessed
    with no referrer — suspicious, suggests automated access.
    """
    depth = len([s for s in url_path.split("/") if s]) if url_path else 0
    return depth > 2 and (not referrer or referrer == "")


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def profile_session(log: dict) -> dict:
    """
    Reads session-related fields from the log.
    Returns log with web_session_features block added.

    Added block:
    {
        "web_session_features": {
            "session_key":              "sess_a3f9b2c1",
            "is_new_session":           False,
            "request_count":            12,
            "unique_ips_in_session":    2,
            "is_multi_ip_session":      True,
            "unique_agents_in_session": 1,
            "is_agent_consistent":      True,
            "session_duration_seconds": 342.0,
            "is_direct_deep_access":    False,
            "has_referrer":             True
        }
    }
    """

    session_key = _get_session_key(log)
    source_ip   = log.get("source_ip", "unknown")
    user_agent  = log.get("user_agent", "")
    referrer    = log.get("referrer", "")
    url_path    = log.get("url_path", "")
    timestamp   = log.get("timestamp", "")

    session = _session_store[session_key]

    # Is this a new session
    is_new_session = session["request_count"] == 0

    # Update first seen
    if session["first_seen"] is None:
        session["first_seen"] = timestamp

    # Update store
    session["seen_ips"].add(source_ip)
    if user_agent:
        session["seen_user_agents"].add(user_agent)
    if referrer:
        session["seen_referrers"].add(referrer)
    session["request_count"] += 1
    session["last_seen"] = timestamp
    session["url_paths"].append(url_path)
    session["url_paths"] = session["url_paths"][-MAX_PATHS:]

    # Compute features
    unique_ips    = len(session["seen_ips"])
    unique_agents = len(session["seen_user_agents"])
    duration      = _get_session_duration_seconds(
                        session["first_seen"],
                        session["last_seen"]
                    )

    web_session_features = {
        "session_key":              session_key,
        "is_new_session":           is_new_session,
        "request_count":            session["request_count"],
        "unique_ips_in_session":    unique_ips,
        "is_multi_ip_session":      unique_ips > 1,
        "unique_agents_in_session": unique_agents,
        "is_agent_consistent":      unique_agents <= 1,
        "session_duration_seconds": duration,
        "is_direct_deep_access":    _is_direct_deep_access(url_path, referrer),
        "has_referrer":             bool(referrer)
    }

    return {**log, "web_session_features": web_session_features}
