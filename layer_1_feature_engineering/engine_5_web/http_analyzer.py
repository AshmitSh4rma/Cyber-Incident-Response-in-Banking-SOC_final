# http_analyzer.py
#
# PURPOSE:
# Extracts web-specific features from HTTP/HTTPS logs.
# Analyzes request methods, status codes, URL patterns,
# payload sizes, and request rates.
#
# WHY THIS MATTERS:
# Web logs tell a completely different story than network logs.
# A 403 on /admin/login from an external IP with a bot user-agent
# is a credential stuffing attempt — not detectable from
# bytes and packets alone.
#
# PATTERNS DETECTED:
# - Suspicious URL paths (admin, config, backup endpoints)
# - Error rate spikes (4xx/5xx ratios)
# - Abnormal payload sizes (SQLi, command injection)
# - Sensitive HTTP methods (PUT, DELETE, PATCH)
# - Bot/scanner user agents
#
# CALLED BY:
# web_orchestrator.py


from collections import defaultdict

# ─────────────────────────────────────────
# CLASSIFICATIONS
# ─────────────────────────────────────────

# URL path segments that indicate sensitive endpoints
SUSPICIOUS_PATH_SEGMENTS = {
    "admin", "administrator", "wp-admin", "phpmyadmin",
    "config", "configuration", "setup", "install",
    "backup", "dump", "export", "import",
    "shell", "cmd", "exec", "command",
    "passwd", "shadow", "etc", "proc",
    "login", "signin", "auth", "oauth",
    "api", "v1", "v2", "graphql",
    ".env", ".git", ".htaccess", "web.config"
}

# HTTP methods that modify server state — higher risk
SENSITIVE_METHODS = {"PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"}

# Known bot and scanner user agent substrings
BOT_UA_PATTERNS = {
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "go-http-client", "curl",
    "wget", "libwww", "scrapy", "burpsuite",
    "dirbuster", "gobuster", "wfuzz", "hydra"
}

# Status code classifications
CLIENT_ERROR_CODES  = range(400, 500)  # 4xx
SERVER_ERROR_CODES  = range(500, 600)  # 5xx


# ─────────────────────────────────────────
# IN-MEMORY HTTP STORE
# Tracks per-source request history
# ─────────────────────────────────────────

_http_store: dict[str, dict] = defaultdict(lambda: {
    "status_codes":     [],
    "methods":          [],
    "path_depths":      [],
    "payload_sizes":    [],
    "total_requests":   0
})

MAX_HISTORY = 100


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _is_suspicious_path(url_path: str) -> bool:
    """Returns True if any path segment matches suspicious patterns."""
    if not url_path:
        return False
    path_lower = url_path.lower()
    return any(seg in path_lower for seg in SUSPICIOUS_PATH_SEGMENTS)


def _get_path_depth(url_path: str) -> int:
    """Returns the depth of the URL path (number of segments)."""
    if not url_path:
        return 0
    return len([s for s in url_path.split("/") if s])


def _is_bot_user_agent(user_agent: str) -> bool:
    """Returns True if user agent matches known bot/scanner patterns."""
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(pattern in ua_lower for pattern in BOT_UA_PATTERNS)


def _get_error_rate(status_codes: list) -> float:
    """Returns ratio of 4xx and 5xx responses in recent history."""
    if not status_codes:
        return 0.0
    error_count = sum(
        1 for code in status_codes
        if code in CLIENT_ERROR_CODES or code in SERVER_ERROR_CODES
    )
    return round(error_count / len(status_codes), 3)


def _update_http_store(source_key: str, log: dict) -> None:
    """Updates the HTTP store for this source."""
    store = _http_store[source_key]

    status_code  = log.get("http_status_code")
    method       = log.get("http_method")
    url_path     = log.get("url_path", "")
    request_size = log.get("request_size") or 0

    if status_code:
        store["status_codes"].append(status_code)
        store["status_codes"] = store["status_codes"][-MAX_HISTORY:]

    if method:
        store["methods"].append(method)
        store["methods"] = store["methods"][-MAX_HISTORY:]

    store["path_depths"].append(_get_path_depth(url_path))
    store["path_depths"] = store["path_depths"][-MAX_HISTORY:]

    store["payload_sizes"].append(request_size)
    store["payload_sizes"] = store["payload_sizes"][-MAX_HISTORY:]

    store["total_requests"] += 1


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def analyze_http(log: dict) -> dict:
    """
    Reads web-specific fields from the log.
    Returns log with web_http_features block added.

    Added block:
    {
        "web_http_features": {
            "http_method":           "POST",
            "status_code":           403,
            "is_client_error":       True,
            "is_server_error":       False,
            "is_sensitive_method":   False,
            "url_path":              "/admin/login",
            "path_depth":            2,
            "is_suspicious_path":    True,
            "is_bot_user_agent":     False,
            "error_rate":            0.8,
            "avg_payload_size":      2048.0,
            "total_requests_seen":   5
        }
    }
    """

    source_key   = log.get("source_ip", "unknown")
    method       = log.get("http_method", "UNKNOWN")
    status_code  = log.get("http_status_code")
    url_path     = log.get("url_path", "")
    user_agent   = log.get("user_agent", "")

    # Update store before reading history
    _update_http_store(source_key, log)

    store      = _http_store[source_key]
    error_rate = _get_error_rate(store["status_codes"])
    avg_payload = round(
        sum(store["payload_sizes"]) / len(store["payload_sizes"]), 2
    ) if store["payload_sizes"] else 0.0

    web_http_features = {
        "http_method":          method,
        "status_code":          status_code,
        "is_client_error":      status_code in CLIENT_ERROR_CODES if status_code else False,
        "is_server_error":      status_code in SERVER_ERROR_CODES if status_code else False,
        "is_sensitive_method":  method in SENSITIVE_METHODS,
        "url_path":             url_path,
        "path_depth":           _get_path_depth(url_path),
        "is_suspicious_path":   _is_suspicious_path(url_path),
        "is_bot_user_agent":    _is_bot_user_agent(user_agent),
        "error_rate":           error_rate,
        "avg_payload_size":     avg_payload,
        "total_requests_seen":  store["total_requests"]
    }

    return {**log, "web_http_features": web_http_features}
