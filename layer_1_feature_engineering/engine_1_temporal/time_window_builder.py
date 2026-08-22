# time_window_builder.py
#
# PURPOSE:
# Builds time windows from the log's timestamp.
# A time window is simply a labeled bucket that tells downstream extractors
# what "period" this event belongs to.
#
# WHY THIS MATTERS:
# tsfresh needs to know the time context of each event to extract
# meaningful frequency and sequence features.
# Without time windows, all events look equally spaced — which is wrong.
#
# WHAT IT PRODUCES:
# Given a timestamp it tells you:
#   - what 1 minute window this event falls in
#   - what 5 minute window
#   - what 15 minute window
#   - what hour window
#   - whether it is off hours (before 8am or after 8pm)
#   - what part of day it is (morning/afternoon/evening/night)
#
# CALLED BY:
# temporal_orchestrator.py


from datetime import UTC, datetime

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

# Business hours definition
# Anything outside this range is flagged as off_hours
BUSINESS_HOUR_START = 8   # 8:00 AM
BUSINESS_HOUR_END   = 20  # 8:00 PM

# Time of day buckets
# Used for behavioral context — logins at 3am are different from logins at 10am
TIME_OF_DAY_BUCKETS = {
    "night":     (0,  6),    # 00:00 — 05:59
    "morning":   (6,  12),   # 06:00 — 11:59
    "afternoon": (12, 17),   # 12:00 — 16:59
    "evening":   (17, 24),   # 17:00 — 23:59
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parses ISO 8601 timestamp string into a datetime object.
    Handles both UTC 'Z' suffix and '+00:00' offset.
    Falls back to current UTC time if parsing fails.
    """
    try:
        # Replace Z with +00:00 for compatibility
        normalized = timestamp_str.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        # If timestamp is malformed, use current time
        # This ensures the pipeline continues
        return datetime.now(UTC)


def _get_window_label(dt: datetime, window_minutes: int) -> str:
    """
    Returns a string label for the time window this datetime falls in.
    Example for 5-minute window at 02:34:
        → "2024-01-15T02:30"
    This label is used to group events that fall in the same window.
    """
    # Floor the minutes to the nearest window boundary
    floored_minute = (dt.minute // window_minutes) * window_minutes
    return dt.strftime("%Y-%m-%dT%H:") + f"{floored_minute:02d}"


def _get_time_of_day(hour: int) -> str:
    """
    Returns the time of day label for a given hour.
    """
    for label, (start, end) in TIME_OF_DAY_BUCKETS.items():
        if start <= hour < end:
            return label
    return "evening"  # fallback for hour == 24 edge case


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def build_time_windows(log: dict) -> dict:
    """
    Receives the log dict.
    Reads the timestamp field.
    Returns the same dict with a time_windows block added.

    Added block:
    {
        "time_windows": {
            "timestamp_parsed": "2024-01-15T02:34:11+00:00",
            "window_1m":  "2024-01-15T02:34",
            "window_5m":  "2024-01-15T02:30",
            "window_15m": "2024-01-15T02:30",
            "window_1h":  "2024-01-15T02:00",
            "hour_of_day": 2,
            "day_of_week": "Monday",
            "is_weekend": False,
            "is_off_hours": True,
            "time_of_day": "night"
        }
    }
    """

    timestamp_str = log.get("timestamp", "")
    dt = _parse_timestamp(timestamp_str)
    hour = dt.hour

    time_windows = {
        "timestamp_parsed": dt.isoformat(),
        "window_1m":        _get_window_label(dt, 1),
        "window_5m":        _get_window_label(dt, 5),
        "window_15m":       _get_window_label(dt, 15),
        "window_1h":        _get_window_label(dt, 60),
        "hour_of_day":      hour,
        "day_of_week":      dt.strftime("%A"),
        "is_weekend":       dt.weekday() >= 5,
        "is_off_hours":     hour < BUSINESS_HOUR_START or hour >= BUSINESS_HOUR_END,
        "time_of_day":      _get_time_of_day(hour)
    }

    return {**log, "time_windows": time_windows}
