from copy import deepcopy
from urllib.parse import unquote

from layer_3_cis.benchmark_matcher import retrieve_benchmarks

# ─────────────────────────────────────────────────────────────────────────────
# Request-payload signatures → OWASP category.
#
# The detection layer's job is to decide *whether* a request is an attack; this
# is about which control family it violates, and that depends on the payload.
# ATT&CK calls every one of these T1190 "Exploit Public-Facing Application",
# which is correct but too coarse to pick an OWASP category from — so the URL is
# read here rather than relying on the technique id.
#
# Ordered: the first match wins, so specific payloads are listed before the
# broad path checks.
# ─────────────────────────────────────────────────────────────────────────────
PAYLOAD_SIGNATURES: list[tuple[tuple[str, ...], list[str], list[str], str]] = [
    (
        ("union select", "or '1'='1", "or 1=1", "information_schema", "xp_cmdshell",
         "sleep(", "benchmark(", "' --", "'--", "; drop ", "concat("),
        ["injection", "sql_injection", "input_validation"],
        ["sql", "injection", "query", "input"],
        "injection",
    ),
    (
        ("<script", "onerror=", "onload=", "javascript:", "alert(", "document.cookie"),
        ["injection", "input_validation"],
        ["injection", "input", "validation"],
        "injection",
    ),
    (
        (";cmd=", "?cmd=", "&cmd=", "|sh ", "$(", "`id`", "/bin/sh", "wget ", "curl "),
        ["injection", "command_injection", "input_validation"],
        ["injection", "input"],
        "injection",
    ),
    (
        ("../", "..\\", "%2e%2e", "/etc/passwd", "/proc/self"),
        ["access_control", "broken_access_control", "authorization"],
        ["access", "authorization", "permissions"],
        "access control",
    ),
]

# An executable dropped through an upload endpoint is CWE-434, "Unrestricted
# Upload of File with Dangerous Type", which OWASP maps to A04 Insecure Design
# (see CWE-1348, the A04:2021 category). Both halves are required: a plain
# request to /index.php is not a file upload, and uploading a .png is not a
# finding.
EXECUTABLE_EXTENSIONS = (".php", ".jsp", ".jspx", ".asp", ".aspx", ".sh", ".phtml", ".cgi")
UPLOAD_INDICATORS = ("upload", "/uploads/", "fileupload", "import", "attachment")

# Endpoints that should never be reachable from the internet. Reaching one with
# no attack payload is an authorisation failure, not an injection.
PRIVILEGED_PATHS = ("/admin", "/internal", "/actuator", "/.git", "/.env", "/config", "/wp-admin")


def _payload_signal(url: str, method: str) -> tuple[list[str], list[str], list[str]] | None:
    """Classify a request by what it carries. Returns (tags, keywords, section)."""
    decoded = unquote(url).lower()

    for needles, tags, keywords, section in PAYLOAD_SIGNATURES:
        if any(n in decoded for n in needles):
            return tags, keywords, [section]

    lands_executable = decoded.endswith(EXECUTABLE_EXTENSIONS) or any(
        f"{ext}?" in decoded for ext in EXECUTABLE_EXTENSIONS
    )
    if lands_executable and (
        method in {"post", "put"} or any(i in decoded for i in UPLOAD_INDICATORS)
    ):
        return (
            ["secure_design", "business_logic", "architecture"],
            ["design", "logic", "architecture"],
            ["design"],
        )

    return None


def process_web_event(entry: dict) -> dict:
    """
    Map a web/application event to an OWASP Top 10 category.

    Note what this deliberately does NOT do: seed the query with
    `web_application` / `application_security` tags. Those sit on most entries in
    the catalogue, and tags carry a flat weight, so seeding them meant the entry
    holding the most generic tags won every time. Every web event in the demo —
    SQL injection included — came back as "A04 Insecure Design". A query has to
    say something specific or it should say nothing and fall through.
    """
    enriched = deepcopy(entry)
    threat = entry.get("engine_2_threat_intel", {}) or {}
    correlation = entry.get("engine_3_correlation", {}) or {}
    detection = entry.get("detection", {}) or {}
    raw_event = entry.get("raw_event", {}) or {}

    mitre_name = str(threat.get("mitre_technique_name", "") or "").lower()
    mitre_tactic = str(threat.get("mitre_tactic", "") or "").lower()
    threat_type = str(detection.get("threat_type", "") or "").lower()
    label = str(detection.get("label", "") or "").lower()
    url = str(raw_event.get("url", "") or "")
    method = str(raw_event.get("http_method", "") or "").lower()

    query_tags: list[str] = []
    query_keywords: list[str] = []
    section_hint: list[str] = []

    combined_signal = f"{mitre_name} {mitre_tactic} {threat_type} {label}"

    # ── What the request actually carried ────────────────────────────────────
    payload = _payload_signal(url, method)
    if payload:
        tags, keywords, section = payload
        query_tags.extend(tags)
        query_keywords.extend(keywords)
        section_hint.extend(section)
    elif url and any(p in url.lower() for p in PRIVILEGED_PATHS):
        query_tags.extend(["access_control", "broken_access_control", "authorization"])
        query_keywords.extend(["access", "authorization", "privilege"])
        section_hint.append("access control")

    # ── What the detection layer concluded, as a fallback signal ─────────────
    if any(w in combined_signal for w in ("inject", "sqli", "xss", "traversal")):
        query_tags.extend(["injection", "input_validation"])
        query_keywords.extend(["injection", "sql", "input"])
        section_hint.append("injection")

    if any(w in combined_signal for w in ("auth", "credential", "login", "brute", "password")):
        query_tags.extend(["authentication", "login", "credential_security"])
        query_keywords.extend(["login", "credential", "session"])
        section_hint.append("authentication")

    if any(w in combined_signal for w in ("dos", "flood", "rate", "exhaustion")):
        query_tags.extend(["availability", "rate_limiting", "dos_protection"])
        section_hint.append("availability")

    timeline = correlation.get("attack_timeline", []) or []
    for item in timeline:
        detail = str(item.get("detail", "") or "").lower()
        if any(w in detail for w in ("login", "failed", "authentication")):
            query_tags.extend(["authentication", "login_abuse"])
            query_keywords.append("login")
            section_hint.append("authentication")
            break

    matched = retrieve_benchmarks(
        domain="web",
        query_tags=query_tags,
        query_keywords=query_keywords,
        section_hint=section_hint,
        max_results=1,
    )

    enriched["cis_benchmark"] = {
        "framework": "web_owasp_catalog",
        "retrieval_query": {
            "query_tags": query_tags,
            "query_keywords": query_keywords,
            "section_hint": section_hint,
        },
        "matched_benchmarks": matched,
    }

    return enriched
