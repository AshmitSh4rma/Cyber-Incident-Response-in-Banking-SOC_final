# telemetry_analyzer.py
#
# PURPOSE:
# Analyzes IoT telemetry data for anomalies.
# IoT devices are clock-like — they report on fixed intervals
# with values within expected ranges.
# Any deviation from this regularity is a strong anomaly signal.
#
# PATTERNS DETECTED:
# - Reporting interval deviation (device reporting too fast/slow)
# - Sensor value out of expected range
# - Sudden value spike (sensor tampering or malfunction)
# - Missing telemetry (device went silent)
# - Command injection via telemetry payload
#
# CALLED BY:
# iot_orchestrator.py


import math
from collections import defaultdict
from datetime import UTC, datetime

# ─────────────────────────────────────────
# IN-MEMORY TELEMETRY STORE
# Key: device_id
# Value: telemetry history
# ─────────────────────────────────────────

_telemetry_store: dict[str, dict] = defaultdict(lambda: {
    "reading_history":    [],
    "interval_history":   [],
    "last_timestamp":     None,
    "topic_history":      set(),
    "command_count":      0
})

MAX_HISTORY = 100

# Expected sensor value ranges per device type
# Values outside these ranges are flagged
SENSOR_RANGES = {
    "temperature":    (-50,   150),
    "humidity":       (0,     100),
    "pressure":       (800,   1100),
    "battery_level":  (0,     100),
    "default":        (-9999, 9999)
}

# Interval deviation threshold
# If current interval deviates more than this % from average, flag it
INTERVAL_DEVIATION_THRESHOLD = 0.5  # 50% deviation

# Suspicious substrings in MQTT topics or telemetry values
# Possible command injection indicators
SUSPICIOUS_PAYLOAD_PATTERNS = {
    "exec", "eval", "system", "cmd", "shell",
    "wget", "curl", "bash", "powershell", "../"
}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(UTC)


def _get_reporting_interval(device_id: str, current_ts: str) -> float:
    """
    Returns seconds since last report for this device.
    Returns 0.0 if this is the first report.
    """
    last = _telemetry_store[device_id]["last_timestamp"]
    if not last:
        return 0.0
    try:
        diff = (_parse_ts(current_ts) - _parse_ts(last)).total_seconds()
        return abs(diff)
    except Exception:
        return 0.0


def _is_interval_anomalous(device_id: str, current_interval: float) -> bool:
    """
    Returns True if current reporting interval deviates significantly
    from the device's historical average interval.
    """
    history = _telemetry_store[device_id]["interval_history"]
    if len(history) < 5 or current_interval == 0:
        return False

    avg = sum(history) / len(history)
    if avg == 0:
        return False

    deviation = abs(current_interval - avg) / avg
    return deviation > INTERVAL_DEVIATION_THRESHOLD


def _is_value_out_of_range(sensor_reading: float, mqtt_topic: str) -> bool:
    """
    Returns True if sensor reading is outside expected range.
    Infers sensor type from MQTT topic.
    """
    if sensor_reading is None:
        return False

    topic_lower = (mqtt_topic or "").lower()
    sensor_type = "default"

    for key in SENSOR_RANGES:
        if key in topic_lower:
            sensor_type = key
            break

    low, high = SENSOR_RANGES[sensor_type]
    return not (low <= sensor_reading <= high)


def _calculate_value_zscore(device_id: str, current_value: float) -> float:
    """
    Returns z-score of current reading vs device's reading history.
    High z-score = sudden spike = sensor tampering or malfunction.
    """
    history = _telemetry_store[device_id]["reading_history"]
    if len(history) < 5 or current_value is None:
        return 0.0

    mean = sum(history) / len(history)
    variance = sum((x - mean) ** 2 for x in history) / len(history)
    std_dev = math.sqrt(variance)

    if std_dev == 0:
        return 0.0

    return round(abs(current_value - mean) / std_dev, 3)


def _detect_payload_injection(mqtt_topic: str, telemetry_value) -> bool:
    """
    Returns True if MQTT topic or telemetry value contains
    suspicious command injection patterns.
    """
    check_str = f"{mqtt_topic or ''} {str(telemetry_value or '')}".lower()
    return any(pattern in check_str for pattern in SUSPICIOUS_PAYLOAD_PATTERNS)


def _update_telemetry_store(device_id: str, log: dict,
                             interval: float) -> None:
    """Updates the telemetry store for this device."""
    store         = _telemetry_store[device_id]
    reading       = log.get("sensor_reading")
    timestamp     = log.get("timestamp", "")
    mqtt_topic    = log.get("mqtt_topic", "")

    if reading is not None:
        store["reading_history"].append(reading)
        store["reading_history"] = store["reading_history"][-MAX_HISTORY:]

    if interval > 0:
        store["interval_history"].append(interval)
        store["interval_history"] = store["interval_history"][-MAX_HISTORY:]

    if mqtt_topic:
        store["topic_history"].add(mqtt_topic)

    store["last_timestamp"] = timestamp


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def analyze_telemetry(log: dict) -> dict:
    """
    Reads IoT telemetry fields from the log.
    Returns log with iot_telemetry_features block added.

    Added block:
    {
        "iot_telemetry_features": {
            "mqtt_topic":               "building/floor3/hvac/temperature",
            "sensor_reading":           38.7,
            "reporting_interval_sec":   30.0,
            "is_interval_anomalous":    False,
            "is_value_out_of_range":    False,
            "value_zscore":             0.4,
            "is_value_spike":           False,
            "payload_injection_detected": False,
            "unique_topics_seen":       1,
            "sampling_interval":        30
        }
    }
    """

    device_id      = log.get("device_id", "unknown")
    mqtt_topic     = log.get("mqtt_topic", "")
    sensor_reading = log.get("sensor_reading")
    telemetry_val  = log.get("telemetry_value")
    sampling_int   = log.get("sampling_interval")
    timestamp      = log.get("timestamp", "")

    # Get interval before updating store
    current_interval = _get_reporting_interval(device_id, timestamp)
    interval_anomaly = _is_interval_anomalous(device_id, current_interval)

    # Compute features
    out_of_range  = _is_value_out_of_range(sensor_reading, mqtt_topic)
    value_zscore  = _calculate_value_zscore(device_id, sensor_reading)
    is_spike      = value_zscore > 3.0
    injection     = _detect_payload_injection(mqtt_topic, telemetry_val)

    # Update store
    _update_telemetry_store(device_id, log, current_interval)

    store = _telemetry_store[device_id]

    iot_telemetry_features = {
        "mqtt_topic":                mqtt_topic,
        "sensor_reading":            sensor_reading,
        "reporting_interval_sec":    current_interval,
        "is_interval_anomalous":     interval_anomaly,
        "is_value_out_of_range":     out_of_range,
        "value_zscore":              value_zscore,
        "is_value_spike":            is_spike,
        "payload_injection_detected": injection,
        "unique_topics_seen":        len(store["topic_history"]),
        "sampling_interval":         sampling_int
    }

    return {**log, "iot_telemetry_features": iot_telemetry_features}
