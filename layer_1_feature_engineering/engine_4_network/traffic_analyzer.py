# traffic_analyzer.py
#
# PURPOSE:
# Extracts network-specific traffic features from network logs.
# Analyzes bytes, packets, ports, and traffic direction.
#
# WHY THIS MATTERS:
# Generic engines handle time, behavior, and statistics.
# This engine handles what is unique to network logs —
# packet-level data, byte ratios, port classifications,
# and whether traffic is moving inside or outside the network.
#
# TRAFFIC DIRECTION:
# north_south = internal to external or external to internal
# east_west   = internal to internal (lateral movement indicator)
#
# CALLED BY:
# network_orchestrator.py




# ─────────────────────────────────────────
# KNOWN PORT CLASSIFICATIONS
# Common ports and their service names
# Used to flag traffic on unusual ports
# ─────────────────────────────────────────

KNOWN_PORTS = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    80: "http", 110: "pop3", 143: "imap", 161: "snmp",
    162: "snmp_trap", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http_alt", 8443: "https_alt", 27017: "mongodb"
}

# Ports that are high risk even if known
HIGH_RISK_PORTS = {23, 161, 162, 445, 3389, 5900}

# Internal IP ranges (RFC 1918)
INTERNAL_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255")
]


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _ip_to_int(ip: str) -> int:
    """Converts IP string to integer for range comparison."""
    try:
        parts = ip.split(".")
        return (int(parts[0]) << 24 | int(parts[1]) << 16 |
                int(parts[2]) << 8  | int(parts[3]))
    except Exception:
        return 0


def _is_internal_ip(ip: str) -> bool:
    """Returns True if IP falls within RFC 1918 private ranges."""
    ip_int = _ip_to_int(ip)
    for start, end in INTERNAL_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


def _get_traffic_direction(src_ip: str, dst_ip: str) -> str:
    """
    Determines traffic direction based on IP ranges.
    east_west  = both internal (lateral movement risk)
    north_south = one internal one external (ingress/egress)
    external   = both external (unlikely in SOC logs but handled)
    """
    src_internal = _is_internal_ip(src_ip)
    dst_internal = _is_internal_ip(dst_ip)

    if src_internal and dst_internal:
        return "east_west"
    if src_internal or dst_internal:
        return "north_south"
    return "external"


def _classify_port(port: int) -> dict:
    """Returns port classification details."""
    if port is None:
        return {
            "service":       "unknown",
            "is_known_port": False,
            "is_high_risk":  False
        }
    return {
        "service":       KNOWN_PORTS.get(port, "unknown"),
        "is_known_port": port in KNOWN_PORTS,
        "is_high_risk":  port in HIGH_RISK_PORTS
    }


def _calculate_bytes_ratio(bytes_in: int, bytes_out: int) -> float:
    """
    Returns bytes_out / bytes_in ratio.
    High ratio = more data going out than coming in = exfil signal.
    Returns 0.0 if bytes_in is zero or missing.
    """
    if not bytes_in or bytes_in == 0:
        return 0.0
    return round(bytes_out / bytes_in, 3)


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def analyze_traffic(log: dict) -> dict:
    """
    Reads network-specific fields from the log.
    Returns log with network_traffic_features block added.

    Added block:
    {
        "network_traffic_features": {
            "traffic_direction":   "east_west",
            "src_is_internal":     True,
            "dst_is_internal":     True,
            "bytes_ratio":         0.258,
            "dest_port_service":   "ssh",
            "is_known_port":       True,
            "is_high_risk_port":   False,
            "has_tcp_flags":       True,
            "tcp_flag_value":      "SYN",
            "is_syn_only":         True,
            "packet_count":        18,
            "duration_ms":         4500,
            "bytes_per_packet":    86.7
        }
    }
    """

    src_ip    = log.get("source_ip", "")
    dst_ip    = log.get("dest_ip", "")
    bytes_in  = log.get("bytes_in") or 0
    bytes_out = log.get("bytes_out") or 0
    packets   = log.get("packets") or 0
    dest_port = log.get("dest_port")
    tcp_flags = log.get("tcp_flags")
    duration  = log.get("duration_ms") or 0

    direction    = _get_traffic_direction(src_ip, dst_ip)
    port_info    = _classify_port(dest_port)
    bytes_ratio  = _calculate_bytes_ratio(bytes_in, bytes_out)

    # Bytes per packet — useful for detecting fragmented attacks
    bytes_per_packet = round(
        (bytes_in + bytes_out) / packets, 2
    ) if packets > 0 else 0.0

    # SYN-only flag — common in port scans and SYN flood attacks
    is_syn_only = tcp_flags == "SYN" if tcp_flags else False

    network_traffic_features = {
        "traffic_direction":  direction,
        "src_is_internal":    _is_internal_ip(src_ip),
        "dst_is_internal":    _is_internal_ip(dst_ip),
        "bytes_ratio":        bytes_ratio,
        "dest_port_service":  port_info["service"],
        "is_known_port":      port_info["is_known_port"],
        "is_high_risk_port":  port_info["is_high_risk"],
        "has_tcp_flags":      tcp_flags is not None,
        "tcp_flag_value":     tcp_flags,
        "is_syn_only":        is_syn_only,
        "packet_count":       packets,
        "duration_ms":        duration,
        "bytes_per_packet":   bytes_per_packet
    }

    return {**log, "network_traffic_features": network_traffic_features}
