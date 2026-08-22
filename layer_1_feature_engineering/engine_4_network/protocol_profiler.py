# protocol_profiler.py
#
# PURPOSE:
# Profiles the protocol used in the network log.
# Detects protocol anomalies — wrong protocol on a port,
# unusual protocol for this source, deprecated protocols.
#
# WHY THIS MATTERS:
# Attackers often tunnel traffic through unexpected protocols
# or use deprecated protocols with known vulnerabilities.
# SNMPv1 on port 161, Telnet on port 23, HTTP on port 443
# are all protocol anomalies worth flagging.
#
# CALLED BY:
# network_orchestrator.py


from collections import defaultdict

# ─────────────────────────────────────────
# PROTOCOL CLASSIFICATIONS
# ─────────────────────────────────────────

# Expected protocol per port
EXPECTED_PROTOCOLS = {
    22:   "TCP",   23:  "TCP",  25:  "TCP",
    53:   "UDP",   67:  "UDP",  68:  "UDP",
    80:   "TCP",   110: "TCP",  143: "TCP",
    161:  "UDP",   162: "UDP",  389: "TCP",
    443:  "TCP",   445: "TCP",  514: "UDP",
    1433: "TCP",   3306: "TCP", 3389: "TCP",
    5432: "TCP",   8080: "TCP", 8443: "TCP"
}

# Deprecated or inherently risky protocols
DEPRECATED_PROTOCOLS = {"TELNET", "FTP", "HTTP", "SNMPV1", "SNMPV2", "RLOGIN"}

# Tunneling-capable protocols — worth flagging for inspection
TUNNELING_PROTOCOLS = {"ICMP", "DNS", "HTTP", "HTTPS"}


# ─────────────────────────────────────────
# IN-MEMORY PROTOCOL STORE
# Tracks protocol history per source IP
# ─────────────────────────────────────────

_protocol_store: dict[str, set] = defaultdict(set)


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _is_protocol_expected(protocol: str, dest_port: int) -> bool:
    """
    Returns True if the protocol matches what is expected on this port.
    Returns True if port is not in the expected map (unknown port).
    """
    if dest_port not in EXPECTED_PROTOCOLS:
        return True
    return EXPECTED_PROTOCOLS[dest_port].upper() == protocol.upper()


def _is_deprecated(protocol: str) -> bool:
    """Returns True if protocol is deprecated or inherently risky."""
    return protocol.upper() in DEPRECATED_PROTOCOLS


def _is_tunneling_capable(protocol: str) -> bool:
    """Returns True if protocol can be used for data tunneling."""
    return protocol.upper() in TUNNELING_PROTOCOLS


def _is_new_protocol_for_source(source_ip: str, protocol: str) -> bool:
    """Returns True if this source has never used this protocol before."""
    is_new = protocol not in _protocol_store[source_ip]
    _protocol_store[source_ip].add(protocol)
    return is_new


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def profile_protocol(log: dict) -> dict:
    """
    Reads protocol and port fields from the log.
    Returns log with network_protocol_features block added.

    Added block:
    {
        "network_protocol_features": {
            "protocol":                    "TCP",
            "is_protocol_expected":        True,
            "is_deprecated_protocol":      False,
            "is_tunneling_capable":        False,
            "is_new_protocol_for_source":  False,
            "unique_protocols_for_source": 2,
            "protocol_anomaly_detected":   False
        }
    }
    """

    protocol  = log.get("protocol") or "UNKNOWN"
    dest_port = log.get("dest_port")
    source_ip = log.get("source_ip", "unknown")

    expected   = _is_protocol_expected(protocol, dest_port)
    deprecated = _is_deprecated(protocol)
    tunneling  = _is_tunneling_capable(protocol)
    new_proto  = _is_new_protocol_for_source(source_ip, protocol)

    # Anomaly if protocol is unexpected OR deprecated
    anomaly_detected = not expected or deprecated

    network_protocol_features = {
        "protocol":                   protocol,
        "is_protocol_expected":       expected,
        "is_deprecated_protocol":     deprecated,
        "is_tunneling_capable":       tunneling,
        "is_new_protocol_for_source": new_proto,
        "unique_protocols_for_source": len(_protocol_store[source_ip]),
        "protocol_anomaly_detected":  anomaly_detected
    }

    return {**log, "network_protocol_features": network_protocol_features}
