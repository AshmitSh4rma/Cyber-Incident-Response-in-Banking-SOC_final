from datetime import datetime, timezone
from typing import Any, Dict, List


def _utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing Z."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z"


def _utc_from_epoch(value) -> str:
    """Epoch seconds as an ISO-8601 UTC string with a trailing Z."""
    return datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z"


FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "@timestamp", "TimeGenerated", "CreationTime"],
    "source_ip": ["source_ip", "src_ip", "client_ip", "IpAddress", "ClientIP", "ip"],
    "dest_ip": ["dest_ip", "destination_ip", "dst_ip", "server_ip", "DestinationIP"],
    "log_type": ["log_type", "logType", "LogType", "event_source", "channel"],
    "src_port": ["src_port", "source_port", "SourcePort"],
    "dest_port": ["dest_port", "destination_port", "dst_port", "port", "DestinationPort", "Port"],
    "protocol": ["protocol", "Protocol"],
    "action": ["action", "Action", "ResultStatus", "Status"],
    "event_type": ["event_type", "Operation", "OperationName", "ActivityDisplayName", "EventName"],
    "severity": ["severity", "Severity", "RiskLevel"],
    "user": ["user", "username", "affected_user", "UserId", "UserPrincipalName", "AccountName"],
    "hostname": ["hostname", "host", "affected_host", "DeviceName", "Computer", "HostName"],
    "flagged": ["flagged"],
    "raw_source": ["raw_source", "source", "Source", "Workload", "LogSource"],

    "bytes_in": ["bytes_in", "BytesIn", "ReceivedBytes"],
    "bytes_out": ["bytes_out", "BytesOut", "SentBytes"],
    "packets": ["packets", "Packets"],
    "tcp_flags": ["tcp_flags", "TcpFlags"],
    "duration_ms": ["duration_ms", "DurationMs", "Duration"],
    "icmp_type": ["icmp_type", "IcmpType"],

    "http_method": ["http_method", "HttpMethod", "Method"],
    "http_status_code": ["http_status_code", "http_status", "status_code", "HttpStatusCode", "StatusCode", "ResponseCode"],
    "url_path": ["url_path", "url", "uri", "request_path", "UrlPath", "Uri", "URL", "RequestUri", "SourceRelativeUrl"],
    "response_size": ["response_size", "ResponseSize"],
    "request_size": ["request_size", "RequestSize"],
    "user_agent": ["user_agent", "UserAgent"],
    "referrer": ["referrer", "Referrer"],
    "session_id": ["session_id", "SessionId", "SessionID"],
    "content_type": ["content_type", "ContentType"],

    "device_id": ["device_id", "DeviceId"],
    "device_type": ["device_type", "DeviceType"],
    "firmware_version": ["firmware_version", "FirmwareVersion"],
    "mqtt_topic": ["mqtt_topic", "MqttTopic"],
    "sensor_reading": ["sensor_reading", "SensorReading"],
    "telemetry_value": ["telemetry_value", "TelemetryValue"],
    "sampling_interval": ["sampling_interval", "SamplingInterval"],
    "battery_level": ["battery_level", "BatteryLevel"],
}


def first_present(record: Dict[str, Any], aliases: List[str], default=None):
    for key in aliases:
        if key in record and record[key] is not None:
            return record[key]
    return default


def safe_int(value, default=None):
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default=None):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return default


def normalize_timestamp(value: Any) -> str:
    if not value:
        return _utc_now_iso()

    if isinstance(value, (int, float)):
        return _utc_from_epoch(value)

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return _utc_now_iso()

        if value.endswith("Z"):
            return value

        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            return _utc_now_iso()

    return _utc_now_iso()


def get_used_keys(normalized_aliases: Dict[str, List[str]], record: Dict[str, Any]) -> set:
    used = set()
    for aliases in normalized_aliases.values():
        for alias in aliases:
            if alias in record:
                used.add(alias)
    return used


def normalize_to_ecs(log, log_type):
    return {
        "@timestamp": log.get("timestamp"),
        "log_type": log_type,
        "source": {
            "ip": log.get("src_ip", "")
        },
        "destination": {
            "ip": log.get("dest_ip", ""),
            "port": log.get("dest_port")
        },
        "raw_event": {
            "action": log.get("action", ""),
            "affected_host": log.get("hostname", ""),
            "affected_user": log.get("username", "")
        }
    }

def normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("Incoming record must be a dictionary")

    normalized = {
        "timestamp": normalize_timestamp(first_present(record, FIELD_ALIASES["timestamp"])),
        "source_ip": first_present(record, FIELD_ALIASES["source_ip"]),
        "dest_ip": first_present(record, FIELD_ALIASES["dest_ip"]),
        "src_port": safe_int(first_present(record, FIELD_ALIASES["src_port"]), 0),
        "dest_port": safe_int(first_present(record, FIELD_ALIASES["dest_port"]), 0),
        "protocol": first_present(record, FIELD_ALIASES["protocol"]),
        "action": first_present(record, FIELD_ALIASES["action"], "unknown"),
        "log_type": first_present(record, FIELD_ALIASES["log_type"]),

        "bytes_in": safe_int(first_present(record, FIELD_ALIASES["bytes_in"]), 0),
        "bytes_out": safe_int(first_present(record, FIELD_ALIASES["bytes_out"]), 0),
        "packets": safe_int(first_present(record, FIELD_ALIASES["packets"]), 0),
        "tcp_flags": first_present(record, FIELD_ALIASES["tcp_flags"]),
        "duration_ms": safe_int(first_present(record, FIELD_ALIASES["duration_ms"]), 0),
        "icmp_type": first_present(record, FIELD_ALIASES["icmp_type"]),

        "event_type": first_present(record, FIELD_ALIASES["event_type"], "unknown"),
        "severity": first_present(record, FIELD_ALIASES["severity"], "low"),
        "user": first_present(record, FIELD_ALIASES["user"]),
        "hostname": first_present(record, FIELD_ALIASES["hostname"]),
        "flagged": safe_bool(first_present(record, FIELD_ALIASES["flagged"]), False),
        "raw_source": first_present(record, FIELD_ALIASES["raw_source"], "uploaded_log"),

        "http_method": first_present(record, FIELD_ALIASES["http_method"]),
        "http_status_code": safe_int(first_present(record, FIELD_ALIASES["http_status_code"]), None),
        "url_path": first_present(record, FIELD_ALIASES["url_path"]),
        "response_size": safe_int(first_present(record, FIELD_ALIASES["response_size"]), None),
        "request_size": safe_int(first_present(record, FIELD_ALIASES["request_size"]), None),
        "user_agent": first_present(record, FIELD_ALIASES["user_agent"]),
        "referrer": first_present(record, FIELD_ALIASES["referrer"], ""),
        "session_id": first_present(record, FIELD_ALIASES["session_id"]),
        "content_type": first_present(record, FIELD_ALIASES["content_type"]),

        "device_id": first_present(record, FIELD_ALIASES["device_id"]),
        "device_type": first_present(record, FIELD_ALIASES["device_type"]),
        "firmware_version": first_present(record, FIELD_ALIASES["firmware_version"]),
        "mqtt_topic": first_present(record, FIELD_ALIASES["mqtt_topic"]),
        "sensor_reading": safe_float(first_present(record, FIELD_ALIASES["sensor_reading"]), None),
        "telemetry_value": first_present(record, FIELD_ALIASES["telemetry_value"]),
        "sampling_interval": safe_int(first_present(record, FIELD_ALIASES["sampling_interval"]), None),
        "battery_level": safe_int(first_present(record, FIELD_ALIASES["battery_level"]), None),
    }

    used_keys = get_used_keys(FIELD_ALIASES, record)
    additional_fields = {k: v for k, v in record.items() if k not in used_keys}

    normalized["raw_event"] = record
    normalized["additional_fields"] = additional_fields

    return normalized