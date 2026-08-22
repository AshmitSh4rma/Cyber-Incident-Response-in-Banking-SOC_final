
import soc_config

from .threat_utils import append_reason, as_bool, normalize_text, safe_float

# ─────────────────────────────────────────────────────────────────────────────
# ACTION VOCABULARY
# Collectors label events with an action verb. Map the ones we recognise
# straight onto a threat pattern — this is the strongest single signal we get,
# and it is what the sample/simulated telemetry actually carries.
# ─────────────────────────────────────────────────────────────────────────────

ACTION_PATTERNS = {
    "port_scan":          ("port_scan",                    "Sequential port probing consistent with service discovery"),
    "portscan":           ("port_scan",                    "Sequential port probing consistent with service discovery"),
    "scan":               ("port_scan",                    "Scanning behaviour observed against target host"),
    "recon":              ("port_scan",                    "Reconnaissance activity against target host"),
    "beaconing":          ("beaconing",                    "Periodic outbound callbacks consistent with C2 beaconing"),
    "beacon":             ("beaconing",                    "Periodic outbound callbacks consistent with C2 beaconing"),
    "c2":                 ("beaconing",                    "Traffic pattern consistent with command-and-control channel"),
    "lateral_movement":   ("lateral_movement",             "Internal host-to-host movement outside normal access paths"),
    "credential_abuse":   ("credential_abuse",             "Credential use inconsistent with the established baseline"),
    "credential_access":  ("credential_abuse",             "Credential access attempt observed"),
    # "failed_login" and "login_failure" deliberately do NOT appear here.
    #
    # Brute force is a count, not an event: one failed login is a typo. Mapping
    # the single-record action straight onto brute_force_attempt made the
    # configured "failed logins before we call it an attack" threshold
    # unreachable — the pattern was already set before the count was consulted,
    # so a bank raising it from 3 to 50 saw no change at all. The count rule
    # below is now the only route to this pattern, apart from a collector that
    # explicitly says brute force.
    "brute_force":        ("brute_force_attempt",          "Repeated authentication failures consistent with credential guessing"),
    "web_attack":         ("web_attack",                   "Request pattern consistent with web application attack"),
    "suspicious_request": ("suspicious_web_access",        "Request to a sensitive or unexpected endpoint"),
    "data_exfiltration":  ("data_exfiltration",            "Large outbound transfer inconsistent with baseline"),
    "exfiltration":       ("data_exfiltration",            "Large outbound transfer inconsistent with baseline"),
    "file_encryption":    ("malware_execution",            "Mass file modification consistent with ransomware"),
    "ransomware":         ("malware_execution",            "Mass file modification consistent with ransomware"),
    "malware_execution":  ("malware_execution",            "Known-bad binary or script execution observed"),
    "privilege_escalation": ("privilege_escalation",       "Privilege change outside the approved change window"),
}

# URL/payload signatures for web traffic.
URL_SIGNATURES = [
    (["' or ", "'1'='1", "union select", "sleep(", "benchmark(", "information_schema", "--", "or 1=1"],
     "web_attack", "SQL injection payload detected in request"),
    (["<script", "javascript:", "onerror=", "onload=", "alert("],
     "web_attack", "Cross-site scripting payload detected in request"),
    (["../", "..%2f", "%2e%2e", "/etc/passwd", "boot.ini"],
     "web_attack", "Path traversal attempt detected in request"),
    ([".php", ".jsp", ".asp", "shell", "cmd.php", "upload"],
     "web_attack", "Request targets an uploadable or executable endpoint"),
]

# Endpoints that are sensitive but not inherently an attack on their own.
SENSITIVE_PATHS = ["admin", "login", ".env", "config", "wp-admin", "phpmyadmin", "actuator", ".git"]

# Cleartext / high-risk management protocols.
RISKY_PROTOCOLS = {"telnet", "ftp", "rlogin", "rsh", "tftp", "snmpv1", "snmpv2"}


def map_threat_patterns(event: dict) -> dict:
    log_type = normalize_text(event.get("log_type") or event.get("log_family"))
    action = normalize_text(event.get("action"))
    # Layer 1 normalises the request path to url_path; accept either spelling.
    url = normalize_text(event.get("url") or event.get("url_path"))
    command = normalize_text(event.get("command"))
    protocol = normalize_text(event.get("protocol"))

    temporal = event.get("temporal_features", {}) or {}
    behavioral = event.get("behavioral_features", {}) or {}
    statistical = event.get("statistical_features", {}) or {}
    anomaly = event.get("anomaly_detection", {}) or {}
    identity = event.get("identity_features", {}) or {}

    reasons = []
    patterns = []

    statistical = event.get("pattern_features", {}) or {}
    failed_logins = safe_float(behavioral.get("failed_login_count", 0))
    off_hours = as_bool(temporal.get("is_off_hours"))
    rare_source = as_bool(behavioral.get("rare_source_ip"))
    rare_user = as_bool(behavioral.get("rare_user_activity"))
    anomaly_score = safe_float(anomaly.get("anomaly_score", 0))

    normalized_action = action.replace("-", "").replace(" ", "").replace("_", "")

    is_signin = as_bool(identity.get("is_signin_activity"))
    is_risky_signin = as_bool(identity.get("is_risky_signin"))
    is_new_ip_for_user = as_bool(behavioral.get("is_new_ip_for_user"))
    is_new_user = as_bool(behavioral.get("is_new_user"))

    # ── Action verb → pattern ────────────────────────────────────────────────
    for verb, (pattern, reason) in ACTION_PATTERNS.items():
        if verb.replace("_", "") == normalized_action or verb in action:
            patterns.append(pattern)
            append_reason(reasons, reason)
            break

    # ── Auth / sign-in patterns ──────────────────────────────────────────────
    # An identity provider's risky-signin verdict stands on its own; otherwise the
    # log has to be an auth log *and* describe a login before these rules apply.
    is_login_action = any(x in normalized_action for x in ("login", "signin"))
    if is_signin or (log_type == "auth" and is_login_action):
        # Count only. This used to read `>= threshold or is_failed`, which made
        # the threshold decorative: a single failed login already satisfied the
        # second clause, so "how many failures is an attack" could not answer
        # anything. One mistyped password is not an attack at any setting.
        threshold = soc_config.get_int("detection.brute_force_attempts")
        if failed_logins >= threshold:
            patterns.append("brute_force_attempt")
            append_reason(
                reasons,
                f"{int(failed_logins)} failed authentication attempts "
                f"(threshold {threshold})",
            )

        if is_new_ip_for_user or rare_source:
            patterns.append("suspicious_login_behavior")
            append_reason(reasons, "Login from unusual or new IP for user")

        if is_new_user or rare_user:
            append_reason(reasons, "Unusual user activity detected")

        if is_risky_signin:
            patterns.append("risky_signin_detected")
            append_reason(reasons, "Identity signals indicate risky sign-in")

        if off_hours:
            append_reason(reasons, "Authentication during off-hours")

    # ── Statistical detections from Layer 1 ──────────────────────────────────
    # These are the only route to a verdict when a log carries no action label,
    # which is the normal case for real network telemetry. The flags were computed
    # and then read by nothing, so the thresholds behind them — including the
    # configurable outbound/inbound ratio — governed nothing at all.
    if as_bool(statistical.get("exfiltration_detected")):
        patterns.append("data_exfiltration")
        append_reason(reasons, "Outbound volume far exceeds inbound for this source")

    if as_bool(statistical.get("port_scan_detected")):
        patterns.append("port_scan")
        append_reason(reasons, "Many distinct ports contacted from one source")

    if as_bool(statistical.get("lateral_movement_detected")):
        patterns.append("lateral_movement")
        append_reason(reasons, "One source reaching an unusual number of internal hosts")

    # ── Web request payload analysis ─────────────────────────────────────────
    if url:
        for needles, pattern, reason in URL_SIGNATURES:
            if any(n in url for n in needles):
                patterns.append(pattern)
                append_reason(reasons, reason)
                break

        if any(p in url for p in SENSITIVE_PATHS):
            patterns.append("suspicious_web_access")
            append_reason(reasons, "Sensitive endpoint accessed")

    # ── Cleartext management protocol ────────────────────────────────────────
    if protocol in RISKY_PROTOCOLS:
        patterns.append("insecure_protocol_use")
        append_reason(reasons, f"Cleartext management protocol '{protocol}' in use")

    # ── Suspicious command execution ─────────────────────────────────────────
    if any(x in command for x in ["powershell", "cmd", "curl", "wget", "nc", "netcat", "certutil", "bitsadmin"]):
        patterns.append("suspicious_command_execution")
        append_reason(reasons, "Suspicious command execution")

    # ── Supporting behavioural context ───────────────────────────────────────
    if rare_source:
        append_reason(reasons, "Source IP appears unusual for this activity")
    if off_hours:
        append_reason(reasons, "Activity occurred outside business hours")
    if safe_float(statistical.get("z_score", 0)) >= 3:
        append_reason(reasons, "Event frequency is a statistical outlier for this window")

    # ── Generic anomaly fallback ─────────────────────────────────────────────
    if anomaly_score > 0.85 and not patterns:
        patterns.append("anomalous_activity")
        append_reason(reasons, "High anomaly score detected")

    # de-duplicate while preserving priority order
    deduped = []
    for p in patterns:
        if p not in deduped:
            deduped.append(p)

    return {
        "matched_patterns": deduped,
        "reasoning": reasons
    }
