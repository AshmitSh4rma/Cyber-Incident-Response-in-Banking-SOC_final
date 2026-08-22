"""
Patch CMP-002 and CMP-003 to include all schema fields matching CMP-001.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

db = Path(__file__).resolve().parent / "soc_incidents.db"
conn = sqlite3.connect(str(db))
conn.row_factory = sqlite3.Row

stored = {r[0] for r in conn.execute("SELECT campaign_id FROM campaigns").fetchall()}

# Load all incidents
incident_rows = conn.execute("SELECT payload FROM incidents").fetchall()
incidents = []
for row in incident_rows:
    try:
        incidents.append(json.loads(row["payload"]))
    except Exception:
        pass

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Kill chain stages in order (mitre-inspired)
KILL_CHAIN = [
    (1,  "Reconnaissance"),
    (2,  "Resource Development"),
    (3,  "Initial Access"),
    (4,  "Execution"),
    (5,  "Persistence"),
    (6,  "Privilege Escalation"),
    (7,  "Defense Evasion"),
    (8,  "Credential Access"),
    (9,  "Discovery"),
    (10, "Lateral Movement"),
    (11, "Collection"),
    (12, "Exfiltration"),
    (13, "Impact"),
]
TOTAL_STAGES = len(KILL_CHAIN)

# Threat type -> kill chain stage mapping
THREAT_STAGE_MAP = {
    "port scan": (1, "Reconnaissance"),
    "network scan": (1, "Reconnaissance"),
    "brute force": (8, "Credential Access"),
    "credential": (8, "Credential Access"),
    "lateral movement": (10, "Lateral Movement"),
    "privilege": (6, "Privilege Escalation"),
    "exfiltration": (12, "Exfiltration"),
    "data exfiltration": (12, "Exfiltration"),
    "malware": (4, "Execution"),
    "ransomware": (13, "Impact"),
    "phishing": (3, "Initial Access"),
    "c2": (4, "Execution"),
    "command and control": (4, "Execution"),
    "persistence": (5, "Persistence"),
    "discovery": (9, "Discovery"),
    "collection": (11, "Collection"),
    "defense evasion": (7, "Defense Evasion"),
}

def sev(inc: dict) -> str:
    return ((inc.get("detection") or {}).get("severity") or "medium").lower()

def get_stage(inc: dict) -> tuple[int, str]:
    threat = ((inc.get("detection") or {}).get("threat_type") or "").lower()
    for key, val in THREAT_STAGE_MAP.items():
        if key in threat:
            return val
    return (3, "Initial Access")

def get_techniques(inc: dict) -> list[str]:
    det = inc.get("detection") or {}
    t = det.get("mitre_technique") or det.get("technique") or det.get("threat_type") or ""
    return [str(t)] if t else []

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Group incidents by campaign
groups: dict[str, list[dict]] = defaultdict(list)
for inc in incidents:
    cmp = inc.get("campaign")
    if isinstance(cmp, dict):
        cid = cmp.get("campaign_id")
        if cid:
            groups[cid].append(inc)

for cid, incs in groups.items():
    if cid == "CMP-001":
        continue  # skip, already correct

    # Severity
    severities = [sev(i) for i in incs]
    worst_sev = min(severities, key=lambda s: SEV_ORDER.get(s, 99))

    # Kill chain: build one entry per unique stage
    stage_map: dict[int, dict] = {}
    for inc in incs:
        order, stage_name = get_stage(inc)
        if order not in stage_map:
            ts = (inc.get("raw_event") or {}).get("timestamp", now_iso())
            techs = get_techniques(inc)
            stage_map[order] = {
                "stage": stage_name,
                "order": order,
                "first_seen": ts,
                "technique": techs[0] if techs else "T0000",
                "technique_name": stage_name,
                "event_id": inc.get("event_id", ""),
            }
    kill_chain = sorted(stage_map.values(), key=lambda x: x["order"])

    furthest_order = max(e["order"] for e in kill_chain) if kill_chain else 1
    furthest_stage = next((e["stage"] for e in kill_chain if e["order"] == furthest_order), "Initial Access")
    progression_pct = round((furthest_order / TOTAL_STAGES) * 100)

    # Actors / assets / accounts / techniques
    actors = list({
        (i.get("dashboard") or {}).get("source_ip") or
        (i.get("raw_event") or {}).get("source_ip", "")
        for i in incs
    } - {""})
    assets = list({
        (i.get("dashboard") or {}).get("affected_host") or
        (i.get("detection") or {}).get("affected_host", "")
        for i in incs
    } - {""})
    accounts = list({
        (i.get("raw_event") or {}).get("user") or ""
        for i in incs
    } - {""})
    techniques = list({
        t for i in incs for t in get_techniques(i)
    })

    linked_by = []
    if actors:
        linked_by.append(f"same source address {actors[0]}")
    if assets:
        linked_by.append(f"shared target asset {assets[0]}")

    first_seen = min(
        (i.get("raw_event") or {}).get("timestamp", now_iso()) for i in incs
    )
    last_seen = max(
        (i.get("raw_event") or {}).get("timestamp", now_iso()) for i in incs
    )

    narrative = (
        f"{len(incs)} alerts correlated into {cid}. "
        f"Worst severity: {worst_sev.upper()}. "
        f"Furthest stage reached: {furthest_stage} (step {furthest_order}/{TOTAL_STAGES}). "
        f"Actors: {', '.join(actors[:3]) or 'unknown'}. "
        f"Assets targeted: {', '.join(assets[:3]) or 'unknown'}."
    )

    determined_at = now_iso()
    reportable = worst_sev in ("critical", "high")

    campaign = {
        "campaign_id": cid,
        "name": f"{furthest_stage} campaign from {actors[0] if actors else 'unknown'}",
        "incident_count": len(incs),
        "incident_ids": [i.get("event_id") for i in incs if i.get("event_id")],
        "severity": worst_sev,
        "member_max_severity": worst_sev,
        "escalated": reportable,
        "confidence": 0.78 if worst_sev == "critical" else 0.65,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "furthest_stage": furthest_stage,
        "furthest_stage_order": furthest_order,
        "progression_pct": progression_pct,
        "stages_reached": len(kill_chain),
        "kill_chain": kill_chain,
        "actors": actors[:5],
        "assets": assets[:5],
        "accounts": accounts[:5],
        "techniques": techniques[:10],
        "linked_by": linked_by,
        "narrative": narrative,
        "determined_at": determined_at,
        "notification": {
            "reportable": reportable,
            "confidence": "high" if reportable else "medium",
            "reasons": [
                f"Reached {furthest_stage} stage with {worst_sev} severity",
                f"{len(incs)} correlated alerts across {len(assets)} asset(s)",
            ],
            "determined_at": determined_at,
            "clocks": [],
            "tightest": None,
            "disclaimer": (
                "Decision support only. The institution's compliance function "
                "makes the final determination and owns any required filing."
            ),
        },
    }

    conn.execute(
        "INSERT OR REPLACE INTO campaigns (campaign_id, payload) VALUES (?, ?)",
        (cid, json.dumps(campaign))
    )
    print(f"[OK] Patched {cid}: {len(incs)} incidents, severity={worst_sev}, "
          f"furthest_stage={furthest_stage} ({furthest_order}), "
          f"kill_chain={[e['stage'] for e in kill_chain]}")

conn.commit()
conn.close()
print("All done.")
