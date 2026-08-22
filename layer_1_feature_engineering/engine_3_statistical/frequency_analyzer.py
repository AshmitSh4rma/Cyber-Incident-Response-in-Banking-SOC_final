# frequency_analyzer.py
#
# PURPOSE:
# Performs statistical frequency analysis on the incoming log.
# Detects spikes, calculates z-scores, and identifies
# whether the current event rate is statistically anomalous.
#
# WHY THIS MATTERS:
# Behavioral engine looks at WHO is doing something unusual.
# Statistical engine looks at WHETHER the rate of events itself
# is unusual — regardless of who is doing it.
# A DDoS attack looks normal per-user but anomalous statistically.
#
# HOW Z-SCORE WORKS HERE:
# We maintain a rolling window of event counts per minute.
# Z-score = (current_count - mean) / std_deviation
# High z-score = current rate is far above normal = spike detected.
#
# CALLED BY:
# statistical_orchestrator.py


import math
from collections import deque

# ─────────────────────────────────────────
# IN-MEMORY RATE STORE
# Tracks event counts per 1-minute window
# across ALL sources combined
# Key: window label (e.g. "2024-01-15T02:34")
# Value: count of events in that window
# ─────────────────────────────────────────

_rate_store: dict[str, int] = {}
_rate_history: deque = deque(maxlen=60)  # last 60 one-minute windows

# Minimum windows needed before z-score is meaningful
MIN_WINDOWS_FOR_ZSCORE = 5


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _update_rate_store(window_1m: str) -> int:
    """
    Increments the count for this 1-minute window.
    Returns the updated count.
    """
    if window_1m not in _rate_store:
        _rate_store[window_1m] = 0
        # New window — add previous window count to history
        if len(_rate_store) > 1:
            prev_counts = list(_rate_store.values())[:-1]
            if prev_counts:
                _rate_history.append(prev_counts[-1])

    _rate_store[window_1m] += 1
    return _rate_store[window_1m]


def _calculate_zscore(current_count: int) -> float:
    """
    Calculates z-score of current count against
    the rolling history of window counts.
    Returns 0.0 if not enough history yet.
    """
    if len(_rate_history) < MIN_WINDOWS_FOR_ZSCORE:
        return 0.0

    history = list(_rate_history)
    mean = sum(history) / len(history)
    variance = sum((x - mean) ** 2 for x in history) / len(history)
    std_dev = math.sqrt(variance)

    if std_dev == 0:
        return 0.0

    return round((current_count - mean) / std_dev, 3)


def _get_percentile_rank(current_count: int) -> float:
    """
    Returns what percentile the current count falls in
    relative to recent history.
    0.98 means current count is higher than 98% of recent windows.
    """
    if len(_rate_history) < MIN_WINDOWS_FOR_ZSCORE:
        return 0.5  # neutral when no history

    history = list(_rate_history)
    below = sum(1 for x in history if x < current_count)
    return round(below / len(history), 3)


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def analyze_frequency(log: dict) -> dict:
    """
    Reads time_windows block from the log.
    Updates rate store and computes statistical features.
    Returns log with frequency_features block added.

    Added block:
    {
        "frequency_features": {
            "current_window_count": 47,
            "zscore":               3.4,
            "percentile_rank":      0.98,
            "spike_detected":       True,
            "history_window_count": 45
        }
    }
    """

    time_windows = log.get("time_windows", {})
    window_1m    = time_windows.get("window_1m", "unknown")

    current_count = _update_rate_store(window_1m)
    zscore        = _calculate_zscore(current_count)
    percentile    = _get_percentile_rank(current_count)

    # Spike if z-score exceeds 2.5 standard deviations
    spike_detected = zscore >= 2.5

    frequency_features = {
        "current_window_count": current_count,
        "zscore":               zscore,
        "percentile_rank":      percentile,
        "spike_detected":       spike_detected,
        "history_window_count": len(_rate_history)
    }

    return {**log, "frequency_features": frequency_features}
