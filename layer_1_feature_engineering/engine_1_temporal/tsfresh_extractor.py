# tsfresh_extractor.py
#
# PURPOSE:
# Extracts time-based features from the log using the time windows
# built by time_window_builder.py
#
# WHY THIS MATTERS:
# A single event in isolation tells you very little.
# But 47 events from the same IP in a 5 minute window tells you a lot.
# tsfresh is designed exactly for this — extracting meaningful numbers
# from time series data.
#
# WHAT IT PRODUCES:
# - How many events happened in each time window from this source
# - Whether the event frequency is accelerating
# - Whether this is a first-seen source IP or a known one
# - Sequence position of this event in the current window
#
# IMPORTANT DESIGN NOTE:
# tsfresh in its full form needs a dataframe of multiple events.
# Since we process logs one at a time (streaming), we maintain an
# in-memory event store per source IP that accumulates events
# and allows us to compute frequency features per window.
#
# CALLED BY:
# temporal_orchestrator.py


from collections import defaultdict
from datetime import UTC, datetime

# ─────────────────────────────────────────
# IN-MEMORY EVENT STORE
# Tracks recent events per source IP
# Key: source_ip
# Value: list of timestamps (strings) for recent events
#
# NOTE: This is an in-memory store — it resets when the process restarts.
# In production this would be backed by Redis or a similar fast store.
# For the SOC platform's current architecture this is sufficient.
# ─────────────────────────────────────────

_event_store: dict[str, list[str]] = defaultdict(list)

# Maximum events to keep per source IP
# Prevents unbounded memory growth
MAX_EVENTS_PER_SOURCE = 500


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _parse_ts(ts_str: str) -> datetime:
    """
    Parses ISO timestamp string to datetime.
    Falls back to current UTC time on failure.
    """
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(UTC)


def _count_events_in_window(
    timestamps: list[str],
    current_dt: datetime,
    window_minutes: int
) -> int:
    """
    Counts how many events from the store fall within
    the last N minutes from current_dt.
    """
    count = 0
    for ts_str in timestamps:
        ts_dt = _parse_ts(ts_str)
        diff_minutes = (current_dt - ts_dt).total_seconds() / 60
        if 0 <= diff_minutes <= window_minutes:
            count += 1
    return count


def _is_frequency_accelerating(
    timestamps: list[str],
    current_dt: datetime
) -> bool:
    """
    Checks if event frequency is accelerating.
    Compares count in last 1 minute vs count in previous 1-2 minutes.
    If last 1 minute has more events than the minute before → accelerating.
    """
    last_1m  = _count_events_in_window(timestamps, current_dt, 1)
    last_2m  = _count_events_in_window(timestamps, current_dt, 2)
    prev_1m  = last_2m - last_1m

    # Accelerating if last minute has strictly more events
    return last_1m > prev_1m


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def extract_temporal_features(log: dict) -> dict:
    """
    Receives the log dict (already has time_windows block from builder).
    Updates the in-memory event store for this source IP.
    Extracts frequency and sequence features.
    Returns the same dict with temporal_features block added.

    Added block:
    {
        "temporal_features": {
            "event_count_1m":  14,
            "event_count_5m":  47,
            "event_count_15m": 89,
            "event_count_1h":  203,
            "is_frequency_accelerating": True,
            "is_first_seen_source":      False,
            "sequence_position_in_1m":   14
        }
    }
    """

    source_ip = log.get("source_ip", "unknown")
    timestamp_str = log.get("timestamp", "")
    current_dt = _parse_ts(timestamp_str)

    # ── Check if this is a first-seen source ──
    is_first_seen = source_ip not in _event_store or \
                    len(_event_store[source_ip]) == 0

    # ── Update the event store ──
    _event_store[source_ip].append(timestamp_str)

    # Trim the store if it exceeds the max size
    if len(_event_store[source_ip]) > MAX_EVENTS_PER_SOURCE:
        _event_store[source_ip] = \
            _event_store[source_ip][-MAX_EVENTS_PER_SOURCE:]

    # ── Count events in each window ──
    all_timestamps = _event_store[source_ip]

    count_1m  = _count_events_in_window(all_timestamps, current_dt, 1)
    count_5m  = _count_events_in_window(all_timestamps, current_dt, 5)
    count_15m = _count_events_in_window(all_timestamps, current_dt, 15)
    count_1h  = _count_events_in_window(all_timestamps, current_dt, 60)

    # ── Sequence position in current 1m window ──
    # How many events from this source in the last 1 minute
    # including this one — this IS the sequence position
    sequence_position = count_1m

    # ── Frequency acceleration ──
    accelerating = _is_frequency_accelerating(all_timestamps, current_dt)

    temporal_features = {
        "event_count_1m":            count_1m,
        "event_count_5m":            count_5m,
        "event_count_15m":           count_15m,
        "event_count_1h":            count_1h,
        "is_frequency_accelerating": accelerating,
        "is_first_seen_source":      is_first_seen,
        "sequence_position_in_1m":   sequence_position
    }

    return {**log, "temporal_features": temporal_features}
