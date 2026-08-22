# pattern_detector.py
#
# PURPOSE:
# Detects known statistical patterns across the event stream.
# Looks for sequences and distributions that indicate
# specific attack types — port scans, brute force, data exfil.
#
# WHY THIS MATTERS:
# frequency_analyzer tells you IF the rate is anomalous.
# pattern_detector tells you WHAT the pattern looks like —
# which helps the AI analysis layer name the attack type.
#
# PATTERNS DETECTED:
# - Port scan:     many dest_ports from same source_ip in short window
# - Brute force:   many failed logins from same source in short window
# - Data exfil:    unusually high bytes_out relative to bytes_in
# - Lateral move:  same user appearing on multiple hosts rapidly
#
# CALLED BY:
# statistical_orchestrator.py


from collections import defaultdict

# ─────────────────────────────────────────
# IN-MEMORY PATTERN STORE
# Tracks per-source behavior for pattern detection
# ─────────────────────────────────────────

_pattern_store: dict[str, dict] = defaultdict(lambda: {
    "dest_ports":    set(),
    "failed_logins": 0,
    "bytes_out_history": [],
    "bytes_in_history":  [],
    "hostnames":     set()
})

# Thresholds
PORT_SCAN_THRESHOLD    = 15   # unique ports in store = port scan
BRUTE_FORCE_THRESHOLD  = 10   # failed logins in store = brute force
EXFIL_RATIO_THRESHOLD  = 10.0 # bytes_out / bytes_in ratio = exfil
LATERAL_HOST_THRESHOLD = 3    # unique hosts for same user = lateral move


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _update_pattern_store(log: dict, source_key: str) -> None:
    """Updates the pattern store for this source."""
    store = _pattern_store[source_key]

    dest_port  = log.get("dest_port")
    action     = log.get("action", "")
    bytes_out  = log.get("bytes_out")
    bytes_in   = log.get("bytes_in")
    hostname   = log.get("hostname")

    if dest_port:
        store["dest_ports"].add(dest_port)

    if "fail" in action.lower() or "deny" in action.lower():
        store["failed_logins"] += 1

    if bytes_out is not None:
        store["bytes_out_history"].append(bytes_out)
        # Keep last 100 only
        store["bytes_out_history"] = store["bytes_out_history"][-100:]

    if bytes_in is not None:
        store["bytes_in_history"].append(bytes_in)
        store["bytes_in_history"] = store["bytes_in_history"][-100:]

    if hostname:
        store["hostnames"].add(hostname)


def _detect_port_scan(source_key: str) -> bool:
    return len(_pattern_store[source_key]["dest_ports"]) >= PORT_SCAN_THRESHOLD


def _detect_brute_force(source_key: str) -> bool:
    return _pattern_store[source_key]["failed_logins"] >= BRUTE_FORCE_THRESHOLD


def _detect_exfiltration(source_key: str) -> bool:
    store     = _pattern_store[source_key]
    out_hist  = store["bytes_out_history"]
    in_hist   = store["bytes_in_history"]

    if not out_hist or not in_hist:
        return False

    avg_out = sum(out_hist) / len(out_hist)
    avg_in  = sum(in_hist)  / len(in_hist)

    if avg_in == 0:
        return False

    return (avg_out / avg_in) >= EXFIL_RATIO_THRESHOLD


def _detect_lateral_movement(source_key: str) -> bool:
    return len(_pattern_store[source_key]["hostnames"]) >= LATERAL_HOST_THRESHOLD


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def detect_patterns(log: dict) -> dict:
    """
    Reads the log and updates pattern store.
    Detects known attack patterns statistically.
    Returns log with pattern_features block added.

    Added block:
    {
        "pattern_features": {
            "port_scan_detected":      False,
            "brute_force_detected":    True,
            "exfiltration_detected":   False,
            "lateral_movement_detected": False,
            "unique_ports_seen":       4,
            "failed_login_count":      11,
            "avg_bytes_out":           320.0,
            "unique_hosts_seen":       1
        }
    }
    """

    source_key = log.get("source_ip", "unknown")

    _update_pattern_store(log, source_key)

    store     = _pattern_store[source_key]
    out_hist  = store["bytes_out_history"]
    avg_out   = round(sum(out_hist) / len(out_hist), 2) if out_hist else 0.0

    pattern_features = {
        "port_scan_detected":        _detect_port_scan(source_key),
        "brute_force_detected":      _detect_brute_force(source_key),
        "exfiltration_detected":     _detect_exfiltration(source_key),
        "lateral_movement_detected": _detect_lateral_movement(source_key),
        "unique_ports_seen":         len(store["dest_ports"]),
        "failed_login_count":        store["failed_logins"],
        "avg_bytes_out":             avg_out,
        "unique_hosts_seen":         len(store["hostnames"])
    }

    return {**log, "pattern_features": pattern_features}
