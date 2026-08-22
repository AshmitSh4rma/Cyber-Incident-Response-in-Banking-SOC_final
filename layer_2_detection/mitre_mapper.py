"""
MITRE ATT&CK mapping for Layer 2 detections.

Every detection gets stamped with the ATT&CK technique(s) it corresponds to and
the tactic those techniques serve. Two reasons this matters beyond labelling:

  1. Tactics are ordered. An intruder progresses Reconnaissance -> Initial Access
     -> ... -> Impact. Once each incident carries a tactic, Layer 2.5 can sort a
     group of incidents into a kill chain and tell an analyst how far along an
     intrusion actually is.
  2. It is the vocabulary SOC teams and auditors already use. "T1110 Brute Force"
     communicates instantly where "brute_force_attempt" needs translating.

Tactic set verified against https://attack.mitre.org/tactics/enterprise/
(15 Enterprise tactics; note TA0005 is "Stealth" and TA0112 "Defense Impairment"
in the current matrix — the older name for TA0005 was "Defense Evasion").
"""

from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# TACTICS — ordered by position in the attack lifecycle.
# `order` drives kill-chain progression scoring in the campaign correlator.
# ─────────────────────────────────────────────────────────────────────────────

TACTICS: list[dict[str, Any]] = [
    {"id": "TA0043", "name": "Reconnaissance",        "order": 1},
    {"id": "TA0042", "name": "Resource Development",  "order": 2},
    {"id": "TA0001", "name": "Initial Access",        "order": 3},
    {"id": "TA0002", "name": "Execution",             "order": 4},
    {"id": "TA0003", "name": "Persistence",           "order": 5},
    {"id": "TA0004", "name": "Privilege Escalation",  "order": 6},
    {"id": "TA0005", "name": "Stealth",               "order": 7},
    {"id": "TA0112", "name": "Defense Impairment",    "order": 8},
    {"id": "TA0006", "name": "Credential Access",     "order": 9},
    {"id": "TA0007", "name": "Discovery",             "order": 10},
    {"id": "TA0008", "name": "Lateral Movement",      "order": 11},
    {"id": "TA0009", "name": "Collection",            "order": 12},
    {"id": "TA0011", "name": "Command and Control",   "order": 13},
    {"id": "TA0010", "name": "Exfiltration",          "order": 14},
    {"id": "TA0040", "name": "Impact",                "order": 15},
]

TACTIC_BY_ID = {t["id"]: t for t in TACTICS}


def _tech(technique_id: str, name: str, tactic_id: str) -> dict[str, Any]:
    tactic = TACTIC_BY_ID[tactic_id]
    return {
        "technique_id": technique_id,
        "technique_name": name,
        "tactic_id": tactic_id,
        "tactic_name": tactic["name"],
        "tactic_order": tactic["order"],
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }


# ─────────────────────────────────────────────────────────────────────────────
# THREAT TYPE -> TECHNIQUES
# Keyed on the threat types Layer 2's classifier emits. The first entry is the
# primary technique; later entries are corroborating context.
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUE_MAP: dict[str, list[dict[str, Any]]] = {
    "port_scan": [
        _tech("T1595.001", "Active Scanning: Scanning IP Blocks", "TA0043"),
        _tech("T1046", "Network Service Discovery", "TA0007"),
    ],
    "brute_force_attempt": [
        _tech("T1110.001", "Brute Force: Password Guessing", "TA0006"),
    ],
    "credential_abuse": [
        _tech("T1078", "Valid Accounts", "TA0001"),
        _tech("T1110", "Brute Force", "TA0006"),
    ],
    "web_attack": [
        _tech("T1190", "Exploit Public-Facing Application", "TA0001"),
    ],
    "suspicious_web_access": [
        _tech("T1595.003", "Active Scanning: Wordlist Scanning", "TA0043"),
    ],
    "beaconing": [
        _tech("T1071.001", "Application Layer Protocol: Web Protocols", "TA0011"),
        _tech("T1573", "Encrypted Channel", "TA0011"),
    ],
    "lateral_movement": [
        _tech("T1021", "Remote Services", "TA0008"),
        _tech("T1078", "Valid Accounts", "TA0001"),
    ],
    "data_exfiltration": [
        _tech("T1041", "Exfiltration Over C2 Channel", "TA0010"),
        _tech("T1048", "Exfiltration Over Alternative Protocol", "TA0010"),
    ],
    "malware_execution": [
        _tech("T1059", "Command and Scripting Interpreter", "TA0002"),
        _tech("T1486", "Data Encrypted for Impact", "TA0040"),
    ],
    "suspicious_command_execution": [
        _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "TA0002"),
        _tech("T1027", "Obfuscated Files or Information", "TA0005"),
    ],
    "privilege_escalation": [
        _tech("T1068", "Exploitation for Privilege Escalation", "TA0004"),
    ],
    "insecure_protocol_use": [
        _tech("T1552", "Unsecured Credentials", "TA0006"),
    ],
    "suspicious_login_behavior": [
        _tech("T1078", "Valid Accounts", "TA0001"),
    ],
    "risky_signin_detected": [
        _tech("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001"),
    ],
    "webshell_upload": [
        _tech("T1505.003", "Server Software Component: Web Shell", "TA0003"),
    ],
    "anomalous_activity": [],
}

# Payload-level refinements. When Layer 4 identified a specific web payload class,
# name the precise technique instead of the generic "exploit public-facing app".
WEB_PAYLOAD_TECHNIQUES: dict[str, dict[str, Any]] = {
    "sql injection": _tech("T1190", "Exploit Public-Facing Application", "TA0001"),
    "cross-site scripting": _tech("T1059.007", "Command and Scripting Interpreter: JavaScript", "TA0002"),
    "path traversal": _tech("T1083", "File and Directory Discovery", "TA0007"),
    "webshell / file upload abuse": _tech("T1505.003", "Server Software Component: Web Shell", "TA0003"),
}


def map_attack(threat_type: str, url: str = "", command: str = "") -> dict[str, Any]:
    """
    Return the ATT&CK block for a detection.

    Shape:
        {
          "techniques":   [ {technique_id, technique_name, tactic_id, ...}, ... ],
          "primary":      { ...the headline technique... } | None,
          "tactics":      [ {id, name, order}, ... ]  (deduplicated)
          "kill_chain_stage": "Lateral Movement" | "unmapped",
          "kill_chain_order": int  (0 when unmapped)
        }
    """
    key = str(threat_type or "").strip().lower()
    techniques = list(TECHNIQUE_MAP.get(key, []))

    # Sharpen web attacks using the observed payload.
    lowered_url = str(url or "").lower()
    if key == "web_attack" and lowered_url:
        if any(s in lowered_url for s in ("' or ", "'1'='1", "union select", "or 1=1")):
            techniques = [WEB_PAYLOAD_TECHNIQUES["sql injection"]] + techniques[1:]
        elif any(s in lowered_url for s in ("<script", "javascript:", "onerror=")):
            techniques = [WEB_PAYLOAD_TECHNIQUES["cross-site scripting"]] + techniques
        elif any(s in lowered_url for s in ("../", "%2e%2e", "/etc/passwd")):
            techniques = [WEB_PAYLOAD_TECHNIQUES["path traversal"]] + techniques
        elif any(s in lowered_url for s in (".php", ".jsp", ".asp", "shell", "upload")):
            techniques = [WEB_PAYLOAD_TECHNIQUES["webshell / file upload abuse"]] + techniques

    lowered_cmd = str(command or "").lower()
    if lowered_cmd and any(s in lowered_cmd for s in ("powershell", "cmd.exe", "certutil", "bitsadmin")):
        extra = _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "TA0002")
        if all(t["technique_id"] != extra["technique_id"] for t in techniques):
            techniques.append(extra)

    # Deduplicate, preserving order.
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for t in techniques:
        if t["technique_id"] not in seen:
            seen.add(t["technique_id"])
            deduped.append(t)

    primary = deduped[0] if deduped else None

    # Distinct tactics, ordered by lifecycle position.
    tactics: list[dict[str, Any]] = []
    tactic_seen: set[str] = set()
    for t in deduped:
        if t["tactic_id"] not in tactic_seen:
            tactic_seen.add(t["tactic_id"])
            tactics.append(
                {
                    "id": t["tactic_id"],
                    "name": t["tactic_name"],
                    "order": t["tactic_order"],
                }
            )
    tactics.sort(key=lambda x: x["order"])

    # The kill-chain stage follows the PRIMARY technique, not the furthest
    # corroborating one. External port scanning cites both Active Scanning
    # (Reconnaissance) and Network Service Discovery (Discovery); taking the
    # furthest would rank a scan later in the lifecycle than a working exploit,
    # which is backwards. Campaign-level progression is computed across
    # incidents in Layer 2.5, which is where "how far in are they" belongs.
    if primary:
        stage = primary["tactic_name"]
        stage_order = primary["tactic_order"]
    else:
        stage, stage_order = "unmapped", 0

    return {
        "techniques": deduped,
        "primary": primary,
        "tactics": tactics,
        "kill_chain_stage": stage,
        "kill_chain_order": stage_order,
        "framework": "MITRE ATT&CK Enterprise",
    }


def enrich_event(event: dict) -> dict:
    """Stamp `mitre_attack` onto an event using its detection verdict."""
    detection = event.get("detection") or {}
    raw_event = event.get("raw_event") or {}

    event["mitre_attack"] = map_attack(
        threat_type=detection.get("threat_type", ""),
        url=event.get("url") or event.get("url_path") or raw_event.get("url") or "",
        command=raw_event.get("command") or event.get("command") or "",
    )
    return event
