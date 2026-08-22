"""
Regulatory notification clocks.

Every incident-response tool tells you how bad something is. In a regulated bank
the more urgent question is *how long you have left to tell someone*, because a
missed notification deadline is a violation in its own right — independent of
whatever the attacker actually achieved.

Those clocks do not start when the attack starts. They start at a **determination**:
"classified as a major ICT incident", "determined to be material", "noticed". That
is exactly the moment this pipeline produces a verdict, which is why the clock can
be started automatically here and nowhere earlier.

Scope, stated plainly
---------------------
This is decision support, not a compliance filing and not legal advice. The
pipeline can say "this looks like a reportable incident and here is the clock you
are probably on"; a bank's compliance function makes the actual determination and
owns the filing. Every threshold below is a heuristic, is labelled as one in the
output, and is deliberately conservative — it would rather raise a clock that
compliance stands down than stay silent on one that mattered.

Sources for the deadlines themselves are in REGIMES below; they are regulation,
not opinion.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# The regimes. Deadlines are from the regulation; the `applies_when` note says
# in plain words which incidents each one is really about.
# ─────────────────────────────────────────────────────────────────────────────

REGIMES: list[dict[str, Any]] = [
    {
        "id": "dora",
        "authority": "EU — DORA",
        "instrument": "Regulation (EU) 2022/2554, RTS on incident reporting, Art. 5",
        "hours": 4,
        "clock_label": "4 hours",
        "starts_from": "classification of the incident as major",
        "applies_when": "Financial entities operating in the EU, for major ICT incidents.",
        "note": (
            "Initial notification within 4 hours of classifying the incident as major, "
            "and no later than 24 hours from becoming aware. Intermediate report at 72 "
            "hours, final within one month."
        ),
        "effective": "17 January 2025",
        "url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
    },
    {
        "id": "cert_in",
        "authority": "India — CERT-In",
        "instrument": "Directions under s.70B(6), IT Act 2000 — No. 20(3)/2022",
        "hours": 6,
        "clock_label": "6 hours",
        "starts_from": "noticing the incident",
        "applies_when": "Any body corporate operating in India, for a broad list of incident types.",
        "note": (
            "Reporting within 6 hours of noticing. The reportable list is unusually wide "
            "and explicitly includes probing and scanning of critical networks."
        ),
        "effective": "28 April 2022",
        "url": "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf",
    },
    {
        "id": "us_banking",
        "authority": "US — OCC / Federal Reserve / FDIC",
        "instrument": "Computer-Security Incident Notification Rule, 86 FR 66424",
        "hours": 36,
        "clock_label": "36 hours",
        "starts_from": "determining a notification incident has occurred",
        "applies_when": (
            "US banking organisations, where the incident materially disrupts operations, "
            "the ability to deliver banking services, or financial-sector stability."
        ),
        "note": "Notify the primary federal regulator no later than 36 hours after determination.",
        "effective": "1 May 2022 (compliance date)",
        "url": "https://www.federalregister.gov/documents/2021/11/23/2021-25510/computer-security-incident-notification-requirements-for-banking-organizations-and-their-bank",
    },
    {
        "id": "sec_8k",
        "authority": "US — SEC Item 1.05",
        "instrument": "Release 33-11216, Form 8-K Item 1.05",
        "hours": 96,  # four business days, approximated as 96h — see caveat below
        "clock_label": "4 business days",
        "starts_from": "determining the incident is material",
        "applies_when": "SEC registrants, for cybersecurity incidents determined to be material.",
        "note": (
            "Disclosure within four BUSINESS days of the materiality determination. The "
            "countdown shown here uses 96 calendar hours as a stand-in and will therefore "
            "read pessimistically across a weekend — treat it as an ordering hint, not the "
            "filing deadline."
        ),
        "effective": "26 July 2023",
        "url": "https://www.sec.gov/newsroom/press-releases/2023-139",
    },
]

REGIME_BY_ID = {r["id"]: r for r in REGIMES}

# Kill-chain stage order at which an intruder has a foothold rather than a probe.
_POST_COMPROMISE = 3  # Initial Access

# Stages that imply data may already have moved or systems were altered.
_DATA_AT_RISK_STAGES = {"Exfiltration", "Impact", "Collection"}

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _now() -> datetime:
    return datetime.now(UTC)


def _parse(ts: Any) -> datetime | None:
    text = str(ts or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def assess_reportability(
    severity: str,
    stage_order: int,
    stage_name: str,
    threat_type: str,
    verdict: str,
) -> dict[str, Any]:
    """
    Would a compliance team plausibly have to notify a regulator about this?

    Returns the answer plus the reasoning, because "you may have 4 hours to file"
    is a claim that has to be defensible on sight.
    """
    reasons: list[str] = []
    rank = _SEVERITY_RANK.get(str(severity).lower(), 1)
    verdict = str(verdict or "").lower()

    # Benign and analyst-dismissed activity is never reportable.
    if verdict in {"benign", "suppressed"}:
        return {
            "reportable": False,
            "confidence": "high",
            "reasons": ["Not a confirmed threat — no notification obligation arises."],
        }

    data_at_risk = stage_name in _DATA_AT_RISK_STAGES or threat_type == "data_exfiltration"
    post_compromise = stage_order >= _POST_COMPROMISE

    if data_at_risk:
        reasons.append(
            f"Activity reached {stage_name}, so customer or transaction data may already "
            "have been accessed or moved."
        )
    if post_compromise and not data_at_risk:
        reasons.append(
            f"Activity reached {stage_name}, which indicates an actual foothold rather "
            "than an external probe."
        )
    if rank >= 4:
        reasons.append("Severity is critical.")
    elif rank == 3:
        reasons.append("Severity is high.")

    # The threshold: data at risk on its own is enough. Otherwise we want both a
    # foothold and material severity — a high-severity probe that never landed is
    # a security event, not a reportable operational incident.
    reportable = data_at_risk or (post_compromise and rank >= 3)

    if not reportable:
        return {
            "reportable": False,
            "confidence": "medium",
            "reasons": reasons
            or [
                "Activity has not progressed past reconnaissance and does not meet a "
                "materiality threshold on its own."
            ],
        }

    return {
        "reportable": True,
        # High confidence only where data is plausibly gone; otherwise this is a
        # judgement call that compliance should confirm.
        "confidence": "high" if data_at_risk and rank >= 3 else "medium",
        "reasons": reasons,
    }


def build_clocks(
    determined_at: Any,
    severity: str,
    stage_order: int,
    stage_name: str,
    threat_type: str = "",
    verdict: str = "malicious",
    regime_ids: list[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Compute notification clocks for one incident or campaign.

    Args:
        determined_at: when the pipeline reached its verdict — the clock's origin.
        regime_ids:    which regimes this institution is subject to. Defaults to
                       all four, because a demo audience should see the spread;
                       a real deployment would set this once per entity.

    Returns a block with the reportability assessment and, if reportable, one
    countdown per regime, soonest deadline first.
    """
    assessment = assess_reportability(severity, stage_order, stage_name, threat_type, verdict)
    origin = _parse(determined_at) or _now()
    current = now or _now()

    if not assessment["reportable"]:
        return {
            "reportable": False,
            "confidence": assessment["confidence"],
            "reasons": assessment["reasons"],
            "determined_at": origin.isoformat(),
            "clocks": [],
            "tightest": None,
            "disclaimer": _DISCLAIMER,
        }

    chosen = regime_ids or [r["id"] for r in REGIMES]
    clocks: list[dict[str, Any]] = []

    for regime_id in chosen:
        regime = REGIME_BY_ID.get(regime_id)
        if not regime:
            continue

        deadline = origin + timedelta(hours=regime["hours"])
        remaining = (deadline - current).total_seconds()

        if remaining <= 0:
            state = "overdue"
        elif remaining <= regime["hours"] * 3600 * 0.25:
            state = "due_soon"
        else:
            state = "on_track"

        clocks.append(
            {
                "regime_id": regime["id"],
                "authority": regime["authority"],
                "instrument": regime["instrument"],
                "clock_label": regime["clock_label"],
                "starts_from": regime["starts_from"],
                "applies_when": regime["applies_when"],
                "note": regime["note"],
                "url": regime["url"],
                "window_hours": regime["hours"],
                "deadline": deadline.isoformat(),
                "seconds_remaining": int(remaining),
                "state": state,
            }
        )

    clocks.sort(key=lambda c: c["deadline"])

    return {
        "reportable": True,
        "confidence": assessment["confidence"],
        "reasons": assessment["reasons"],
        "determined_at": origin.isoformat(),
        "clocks": clocks,
        "tightest": clocks[0] if clocks else None,
        "disclaimer": _DISCLAIMER,
    }


_DISCLAIMER = (
    "Decision support, not a compliance filing and not legal advice. The pipeline flags "
    "incidents that look reportable and shows the deadline each regime would impose; the "
    "institution's compliance function makes the determination and owns the filing."
)


def for_campaign(campaign: dict, now: datetime | None = None) -> dict[str, Any]:
    """
    Clocks for a correlated campaign.

    A campaign is the right unit here: regulators care about the incident, and nine
    alerts that are one intrusion are one incident with one deadline — not nine.
    """
    return build_clocks(
        determined_at=campaign.get("determined_at") or campaign.get("last_seen"),
        severity=campaign.get("severity", "low"),
        stage_order=int(campaign.get("furthest_stage_order") or 0),
        stage_name=campaign.get("furthest_stage") or "",
        threat_type="",
        verdict="malicious",
        now=now,
    )


def for_incident(incident: dict, now: datetime | None = None) -> dict[str, Any]:
    """Clocks for a standalone incident that is not part of any campaign."""
    detection = incident.get("detection") or {}
    attack = incident.get("mitre_attack") or {}
    raw = incident.get("raw_event") or {}

    return build_clocks(
        determined_at=incident.get("determined_at") or raw.get("timestamp"),
        severity=detection.get("severity", "low"),
        stage_order=int(attack.get("kill_chain_order") or 0),
        stage_name=attack.get("kill_chain_stage") or "",
        threat_type=detection.get("threat_type") or "",
        verdict=detection.get("label") or "suspicious",
        now=now,
    )


def format_remaining(seconds: int) -> str:
    """'3h 12m' / '18m' / 'overdue by 2h 4m' — for direct display."""
    overdue = seconds < 0
    s = abs(int(seconds))
    hours, rem = divmod(s, 3600)
    minutes = rem // 60

    if hours >= 24:
        days, hours = divmod(hours, 24)
        text = f"{days}d {hours}h"
    elif hours:
        text = f"{hours}h {minutes}m"
    else:
        text = f"{minutes}m"

    return f"overdue by {text}" if overdue else text
