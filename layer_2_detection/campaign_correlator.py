"""
Layer 2.5 — Campaign correlation.

Layer 2 answers "is this event malicious?" one event at a time. That is the wrong
unit of analysis for an intrusion. A real intrusion arrives as a dozen separate
alerts across different hosts and hours, and the expensive part of an analyst's
job is realising they are one thing.

This module groups related incidents into campaigns and reports how far the
intruder progressed through the ATT&CK lifecycle.

The linking that matters
------------------------
Naive correlation groups by shared source IP. That misses the most important hop
in any real intrusion: once an attacker owns a host, *that host* becomes the
source of the next alert. So we also link on the compromise chain —

    incident A: 203.0.113.55  ->  web-server-01     (exploit)
    incident B: web-server-01 ->  internal-db-01    (lateral movement)

A's victim is B's attacker. Chaining on that turns two unrelated-looking alerts
into one story with a direction of travel. Connected components over those edges
are the campaigns.
"""

from typing import Any

from layer_2_detection.mitre_mapper import TACTICS

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}

# Addresses that carry no correlation value — linking every incident that touched
# a broadcast or unspecified address would merge unrelated activity into one blob.
_NOISE_PIVOTS = {"", "unknown", "unknown_ip", "0.0.0.0", "255.255.255.255", "none", "null", "-", "n/a"}


def _clean(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "" if text in _NOISE_PIVOTS else text


def _incident_view(event: dict, index: int) -> dict[str, Any]:
    """Flatten the fields the correlator needs out of a pipeline event."""
    detection = event.get("detection") or {}
    raw = event.get("raw_event") or {}
    dash = event.get("dashboard") or {}
    attack = event.get("mitre_attack") or {}

    return {
        "index": index,
        "event_id": event.get("event_id") or f"idx-{index}",
        "timestamp": raw.get("timestamp") or dash.get("timestamp") or event.get("timestamp") or "",
        "source_ip": _clean(dash.get("source_ip") or raw.get("source_ip") or event.get("source_ip")),
        "dest_ip": _clean(dash.get("destination_ip") or raw.get("destination_ip") or event.get("dest_ip")),
        "host": _clean(dash.get("affected_host") or raw.get("affected_host") or raw.get("host") or event.get("hostname")),
        "user": _clean(dash.get("affected_user") or raw.get("affected_user") or raw.get("user") or event.get("user")),
        "threat_type": detection.get("threat_type") or "unknown",
        "severity": str(detection.get("severity") or "low").lower(),
        "confidence": float(detection.get("confidence") or 0.0),
        "label": detection.get("label") or "suspicious",
        "suppressed": bool(detection.get("suppressed")),
        "stage": attack.get("kill_chain_stage") or "unmapped",
        "stage_order": int(attack.get("kill_chain_order") or 0),
        "technique": (attack.get("primary") or {}).get("technique_id") or "",
        "technique_name": (attack.get("primary") or {}).get("technique_name") or "",
    }


class _UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, a: int) -> int:
        while self.parent[a] != a:
            self.parent[a] = self.parent[self.parent[a]]
            a = self.parent[a]
        return a

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


# Initial Access. Below this, the actor never achieved a foothold, so their
# traffic reaching a host does not make that host theirs.
_ACCESS_ACHIEVED = 3


def _link_reason(a: dict, b: dict) -> str | None:
    """
    Why these two incidents belong to the same campaign, or None.

    Ordered strongest-signal-first so the explanation an analyst reads is the
    most compelling true one.
    """
    # Order by time so "victim became attacker" is evaluated in the only
    # direction that makes sense.
    earlier, later = (a, b) if (a["timestamp"] or "") <= (b["timestamp"] or "") else (b, a)

    # The compromise chain: one incident's victim becomes the next one's source.
    #
    # Gated on the earlier incident having actually reached Initial Access or
    # beyond. Without that gate, a scheduled vulnerability scan that merely sent
    # packets to a server gets chained to everything that server later did —
    # which is how an authorised scan ends up inside a breach campaign.
    if earlier["stage_order"] >= _ACCESS_ACHIEVED:
        if earlier["host"] and earlier["host"] == later["source_ip"]:
            return (
                f"{earlier['host']} was compromised at {earlier['stage']}, "
                "then became the source of the next activity"
            )
        if earlier["dest_ip"] and earlier["dest_ip"] == later["source_ip"]:
            return (
                f"activity reached {earlier['dest_ip']} at {earlier['stage']}, "
                "which then originated further activity"
            )

    # Same actor.
    if a["source_ip"] and a["source_ip"] == b["source_ip"]:
        return f"same source address {a['source_ip']}"

    # Same identity under attack.
    if a["user"] and a["user"] == b["user"] and a["user"] != "unattributed":
        return f"same account '{a['user']}' involved"

    # Deliberately NOT linking on "same asset targeted". Every alert in a real
    # network touches some shared server, so that edge bridges unrelated clusters
    # into one useless mega-campaign. Shared infrastructure is not shared intent;
    # only actor, identity, or a genuine compromise chain is.
    return None


def _campaign_name(members: list[dict]) -> str:
    """A name an analyst can say out loud."""
    external = [m for m in members if m["source_ip"] and not _is_internal(m["source_ip"])]
    origin = external[0]["source_ip"] if external else (members[0]["source_ip"] or "an internal host")
    furthest = max(members, key=lambda m: m["stage_order"])

    if furthest["stage_order"] >= 14:
        shape = "Data theft"
    elif furthest["stage_order"] >= 11:
        shape = "Hands-on intrusion"
    elif furthest["stage_order"] >= 9:
        shape = "Credential attack"
    elif furthest["stage_order"] >= 3:
        shape = "Attempted breach"
    else:
        shape = "Reconnaissance"

    return f"{shape} originating from {origin}"


def _is_internal(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or any(ip.startswith(f"172.{n}.") for n in range(16, 32))
    )


def correlate_campaigns(events: list[dict], min_size: int = 2) -> dict[str, Any]:
    """
    Group events into campaigns.

    Args:
        events:   pipeline events carrying `detection` and `mitre_attack`.
        min_size: smallest group that counts as a campaign. Singletons stay
                  standalone incidents — calling one alert a "campaign" would
                  inflate the number and teach an analyst to distrust it.

    Returns:
        {
          "campaigns": [ ...campaign objects, worst first... ],
          "standalone_incident_ids": [...],
          "summary": { counts and the worst progression seen }
        }
    """
    # Only events that actually represent a threat participate. Suppressed events
    # are analyst-dismissed, benign events are normal business traffic, and
    # unmapped events contribute no stage — including any of them pads campaign
    # size and lets ordinary traffic bridge two unrelated clusters.
    views = [_incident_view(e, i) for i, e in enumerate(events)]
    active = [
        v
        for v in views
        if not v["suppressed"]
        and v["label"] in {"suspicious", "malicious"}
        and v["stage_order"] > 0
    ]

    if len(active) < min_size:
        return {
            "campaigns": [],
            "standalone_incident_ids": [v["event_id"] for v in active],
            "summary": {
                "campaign_count": 0,
                "incidents_in_campaigns": 0,
                "standalone_incidents": len(active),
                "worst_stage": "none",
                "worst_stage_order": 0,
            },
        }

    uf = _UnionFind(len(active))
    reasons: dict[tuple[int, int], str] = {}

    for i in range(len(active)):
        for j in range(i + 1, len(active)):
            reason = _link_reason(active[i], active[j])
            if reason:
                uf.union(i, j)
                reasons[(i, j)] = reason

    # Gather connected components.
    groups: dict[int, list[int]] = {}
    for idx in range(len(active)):
        groups.setdefault(uf.find(idx), []).append(idx)

    campaigns: list[dict[str, Any]] = []
    standalone: list[str] = []

    for group_no, (_, member_indices) in enumerate(sorted(groups.items()), start=1):
        members = [active[i] for i in member_indices]

        if len(members) < min_size:
            standalone.extend(m["event_id"] for m in members)
            continue

        members.sort(key=lambda m: (m["timestamp"], m["stage_order"]))

        # Kill chain: one entry per distinct stage reached, in lifecycle order.
        by_stage: dict[str, dict[str, Any]] = {}
        for m in members:
            if m["stage"] == "unmapped":
                continue
            existing = by_stage.get(m["stage"])
            if existing is None or m["timestamp"] < existing["first_seen"]:
                by_stage[m["stage"]] = {
                    "stage": m["stage"],
                    "order": m["stage_order"],
                    "first_seen": m["timestamp"],
                    "technique": m["technique"],
                    "technique_name": m["technique_name"],
                    "event_id": m["event_id"],
                }
        kill_chain = sorted(by_stage.values(), key=lambda s: s["order"])

        furthest = max(members, key=lambda m: m["stage_order"])
        worst_rank = max(_SEVERITY_RANK.get(m["severity"], 1) for m in members)

        # Distinct link reasons within this group, for the "why" line.
        group_set = set(member_indices)
        why = []
        for (i, j), reason in reasons.items():
            if i in group_set and j in group_set and reason not in why:
                why.append(reason)

        timestamps = [m["timestamp"] for m in members if m["timestamp"]]
        actors = sorted({m["source_ip"] for m in members if m["source_ip"]})
        assets = sorted({m["host"] for m in members if m["host"]})
        accounts = sorted({m["user"] for m in members if m["user"] and m["user"] != "unattributed"})

        # A campaign is worse than the sum of its parts: multiple stages reached
        # by one actor is the signal, so escalate severity when the chain is long.
        escalated_rank = worst_rank
        if len(kill_chain) >= 3 and escalated_rank < 4:
            escalated_rank = min(4, escalated_rank + 1)

        campaigns.append(
            {
                "campaign_id": f"CMP-{group_no:03d}",
                "name": _campaign_name(members),
                "incident_count": len(members),
                "incident_ids": [m["event_id"] for m in members],
                "severity": _RANK_TO_SEVERITY[escalated_rank],
                "member_max_severity": _RANK_TO_SEVERITY[worst_rank],
                "escalated": escalated_rank > worst_rank,
                "confidence": round(max(m["confidence"] for m in members), 2),
                "first_seen": min(timestamps) if timestamps else "",
                "last_seen": max(timestamps) if timestamps else "",
                "furthest_stage": furthest["stage"],
                "furthest_stage_order": furthest["stage_order"],
                "progression_pct": round(100 * furthest["stage_order"] / len(TACTICS)),
                "stages_reached": len(kill_chain),
                "kill_chain": kill_chain,
                "actors": actors,
                "assets": assets,
                "accounts": accounts,
                "techniques": sorted({m["technique"] for m in members if m["technique"]}),
                "linked_by": why,
                "narrative": _narrative(members, kill_chain, actors, assets, why),
            }
        )

    campaigns.sort(
        key=lambda c: (_SEVERITY_RANK.get(c["severity"], 1), c["furthest_stage_order"], c["incident_count"]),
        reverse=True,
    )

    worst = campaigns[0] if campaigns else None

    return {
        "campaigns": campaigns,
        "standalone_incident_ids": standalone,
        "summary": {
            "campaign_count": len(campaigns),
            "incidents_in_campaigns": sum(c["incident_count"] for c in campaigns),
            "standalone_incidents": len(standalone),
            "worst_stage": worst["furthest_stage"] if worst else "none",
            "worst_stage_order": worst["furthest_stage_order"] if worst else 0,
        },
    }


def _narrative(
    members: list[dict],
    kill_chain: list[dict],
    actors: list[str],
    assets: list[str],
    why: list[str],
) -> str:
    """Plain-language account of the campaign, for the analyst and the report."""
    if not members:
        return ""

    stages = " -> ".join(s["stage"] for s in kill_chain) or "no mapped stages"

    # Name the external origin. `actors` is sorted, so actors[0] is whichever
    # address sorts first — usually an internal hop, which reads as though the
    # intrusion started inside the network.
    external = [a for a in actors if not _is_internal(a)]
    origin = external[0] if external else (actors[0] if actors else "an unidentified source")
    asset_text = (
        f"{len(assets)} assets ({', '.join(assets[:3])}{'...' if len(assets) > 3 else ''})"
        if len(assets) > 1
        else (assets[0] if assets else "an unidentified asset")
    )

    lead = (
        f"{len(members)} alerts that were raised separately describe a single sequence of activity "
        f"involving {asset_text}, beginning at {origin}."
    )
    chain = f" Observed progression: {stages}."
    linkage = f" Correlated because {why[0]}." if why else ""

    furthest = max(members, key=lambda m: m["stage_order"])
    if furthest["stage_order"] >= 14:
        verdict = (
            " The chain reaches Exfiltration, meaning data may already have left the environment — "
            "treat as an active breach and start the regulatory notification clock."
        )
    elif furthest["stage_order"] >= 11:
        verdict = (
            " The chain reaches Lateral Movement, which indicates a live intruder inside the network "
            "rather than an external probe."
        )
    elif furthest["stage_order"] >= 9:
        verdict = " Credentials are being targeted directly; assume account compromise until disproven."
    elif furthest["stage_order"] >= 3:
        verdict = " Access was attempted but the chain does not yet show post-compromise activity."
    else:
        verdict = " Activity is still pre-compromise reconnaissance."

    return lead + chain + linkage + verdict
