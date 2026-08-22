# device_profiler.py
#
# PURPOSE:
# Builds a behavioral profile for IoT devices.
# Tracks device identity stability, firmware versions,
# and communication patterns.
#
# WHY THIS MATTERS:
# IoT devices are highly predictable — they do the same thing
# on the same schedule every time. Any deviation is suspicious.
# A temperature sensor that suddenly changes its IP, firmware
# version, or reporting destination is a major red flag.
#
# PATTERNS DETECTED:
# - Device IP change (possible device spoofing)
# - Firmware version change (possible firmware tampering)
# - New destination IP (possible C2 communication)
# - Device reporting to unexpected port
#
# CALLED BY:
# iot_orchestrator.py


from collections import defaultdict

# ─────────────────────────────────────────
# IN-MEMORY DEVICE STORE
# Key: device_id
# Value: device history
# ─────────────────────────────────────────

_device_store: dict[str, dict] = defaultdict(lambda: {
    "seen_ips":           set(),
    "seen_firmwares":     set(),
    "seen_dest_ips":      set(),
    "seen_dest_ports":    set(),
    "seen_protocols":     set(),
    "event_count":        0,
    "last_seen":          None,
    "first_seen":         None
})


# ─────────────────────────────────────────
# KNOWN IOT PROTOCOLS AND PORTS
# ─────────────────────────────────────────

IOT_PROTOCOLS = {"MQTT", "COAP", "MODBUS", "AMQP", "XMPP", "OPCUA"}

EXPECTED_IOT_PORTS = {
    1883:  "mqtt",
    8883:  "mqtt_ssl",
    5683:  "coap",
    5684:  "coap_dtls",
    502:   "modbus",
    4840:  "opcua",
    5672:  "amqp",
    5671:  "amqp_ssl"
}

# Ports that IoT devices should never communicate on
SUSPICIOUS_IOT_PORTS = {22, 23, 80, 443, 3389, 4444, 4445, 9001}


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _update_device_store(device_id: str, log: dict) -> None:
    """Updates the device store with current log data."""
    store     = _device_store[device_id]
    source_ip = log.get("source_ip", "unknown")
    firmware  = log.get("firmware_version")
    dest_ip   = log.get("dest_ip", "unknown")
    dest_port = log.get("dest_port")
    protocol  = log.get("protocol", "unknown")
    timestamp = log.get("timestamp", "")

    store["seen_ips"].add(source_ip)
    store["seen_dest_ips"].add(dest_ip)
    store["seen_protocols"].add(protocol)

    if firmware:
        store["seen_firmwares"].add(firmware)
    if dest_port:
        store["seen_dest_ports"].add(dest_port)

    if store["first_seen"] is None:
        store["first_seen"] = timestamp

    store["last_seen"] = timestamp
    store["event_count"] += 1


def _detect_ip_change(device_id: str, _current_ip: str) -> bool:
    """
    Returns True if this device has been seen with a different IP before.
    IoT devices typically have static IPs — any change is suspicious.
    """
    seen_ips = _device_store[device_id]["seen_ips"]
    return len(seen_ips) > 1


def _detect_firmware_change(device_id: str) -> bool:
    """
    Returns True if this device has been seen with multiple firmware versions.
    Firmware changes outside maintenance windows are suspicious.
    """
    return len(_device_store[device_id]["seen_firmwares"]) > 1


def _detect_new_destination(device_id: str, _current_dest: str) -> bool:
    """
    Returns True if device is communicating with a new destination IP.
    Possible C2 or data exfiltration indicator.
    """
    return len(_device_store[device_id]["seen_dest_ips"]) > 1


def _detect_suspicious_port(dest_port: int) -> bool:
    """Returns True if destination port is suspicious for an IoT device."""
    if dest_port is None:
        return False
    return dest_port in SUSPICIOUS_IOT_PORTS


def _is_known_iot_protocol(protocol: str) -> bool:
    """Returns True if protocol is a known IoT protocol."""
    return protocol.upper() in IOT_PROTOCOLS


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def profile_device(log: dict) -> dict:
    """
    Reads IoT device fields from the log.
    Returns log with iot_device_features block added.

    Added block:
    {
        "iot_device_features": {
            "device_id":                "SENSOR-HVAC-007",
            "device_type":              "hvac_controller",
            "firmware_version":         "2.1.4",
            "is_new_device":            False,
            "ip_change_detected":       False,
            "firmware_change_detected": False,
            "new_destination_detected": False,
            "suspicious_port_detected": False,
            "is_known_iot_protocol":    True,
            "unique_ips_seen":          1,
            "unique_destinations_seen": 1,
            "total_device_events":      47
        }
    }
    """

    device_id   = log.get("device_id", "unknown")
    device_type = log.get("device_type", "unknown")
    firmware    = log.get("firmware_version", "unknown")
    source_ip   = log.get("source_ip", "unknown")
    dest_ip     = log.get("dest_ip", "unknown")
    dest_port   = log.get("dest_port")
    protocol    = log.get("protocol", "unknown")

    store = _device_store[device_id]

    # Is this a new device
    is_new_device = store["event_count"] == 0

    # Update store AFTER checking is_new
    _update_device_store(device_id, log)

    iot_device_features = {
        "device_id":                device_id,
        "device_type":              device_type,
        "firmware_version":         firmware,
        "is_new_device":            is_new_device,
        "ip_change_detected":       _detect_ip_change(device_id, source_ip),
        "firmware_change_detected": _detect_firmware_change(device_id),
        "new_destination_detected": _detect_new_destination(device_id, dest_ip),
        "suspicious_port_detected": _detect_suspicious_port(dest_port),
        "is_known_iot_protocol":    _is_known_iot_protocol(protocol),
        "unique_ips_seen":          len(store["seen_ips"]),
        "unique_destinations_seen": len(store["seen_dest_ips"]),
        "total_device_events":      store["event_count"]
    }

    return {**log, "iot_device_features": iot_device_features}
