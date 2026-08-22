"""
Tests for regulatory notification clocks.

The risk here is not a wrong countdown — it is telling a bank it must notify a
regulator when it must not, or staying silent when it must. So most of these test
the reportability threshold rather than the arithmetic.
"""

from datetime import UTC, datetime, timedelta

import pytest

from regulatory_clock import (
    REGIMES,
    assess_reportability,
    build_clocks,
    for_campaign,
    format_remaining,
)

T0 = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)


# ─────────────────────────────────────────────────────────────────────────────
# The regimes themselves
# ─────────────────────────────────────────────────────────────────────────────

def test_every_regime_carries_its_source():
    """A deadline asserted without an instrument is not defensible."""
    assert len(REGIMES) == 4
    for regime in REGIMES:
        assert regime["hours"] > 0
        assert regime["instrument"]
        assert regime["url"].startswith("http")
        assert regime["starts_from"]
        assert regime["applies_when"]


def test_dora_is_the_tightest_clock():
    tightest = min(REGIMES, key=lambda r: r["hours"])
    assert tightest["id"] == "dora"
    assert tightest["hours"] == 4


def test_sec_clock_declares_its_business_day_approximation():
    """96 calendar hours is a stand-in for four business days; say so."""
    sec = next(r for r in REGIMES if r["id"] == "sec_8k")
    assert sec["clock_label"] == "4 business days"
    assert "business" in sec["note"].lower()
    assert "stand-in" in sec["note"].lower() or "pessimistic" in sec["note"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Reportability — the part that matters
# ─────────────────────────────────────────────────────────────────────────────

def test_benign_activity_is_never_reportable():
    for verdict in ("benign", "suppressed"):
        result = assess_reportability("critical", 14, "Exfiltration", "data_exfiltration", verdict)
        assert result["reportable"] is False
        assert result["confidence"] == "high"


def test_exfiltration_is_reportable_with_high_confidence():
    result = assess_reportability("critical", 14, "Exfiltration", "data_exfiltration", "malicious")
    assert result["reportable"] is True
    assert result["confidence"] == "high"
    assert any("data" in r.lower() for r in result["reasons"])


def test_reconnaissance_alone_is_not_reportable():
    """
    A port scan is a security event, not a reportable operational incident. Raising
    a 4-hour regulatory clock for every scan would train a compliance team to
    ignore the feature entirely.
    """
    result = assess_reportability("medium", 1, "Reconnaissance", "port_scan", "suspicious")
    assert result["reportable"] is False
    assert result["reasons"]


def test_high_severity_probe_that_never_landed_is_not_reportable():
    """Severity alone must not trigger a clock without a foothold."""
    result = assess_reportability("critical", 1, "Reconnaissance", "port_scan", "malicious")
    assert result["reportable"] is False


def test_foothold_plus_material_severity_is_reportable():
    result = assess_reportability("high", 3, "Initial Access", "web_attack", "malicious")
    assert result["reportable"] is True


def test_foothold_with_low_severity_is_not_reportable():
    result = assess_reportability("medium", 3, "Initial Access", "web_attack", "suspicious")
    assert result["reportable"] is False


def test_data_at_risk_overrides_low_severity():
    """If data may already be gone, severity bookkeeping should not gate the clock."""
    result = assess_reportability("medium", 14, "Exfiltration", "data_exfiltration", "malicious")
    assert result["reportable"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Clock arithmetic
# ─────────────────────────────────────────────────────────────────────────────

def test_clocks_are_ordered_soonest_first():
    result = build_clocks(T0, "critical", 14, "Exfiltration", "data_exfiltration", "malicious", now=T0)
    assert result["reportable"] is True
    deadlines = [c["deadline"] for c in result["clocks"]]
    assert deadlines == sorted(deadlines)
    assert result["tightest"]["regime_id"] == "dora"


def test_deadline_is_origin_plus_window():
    result = build_clocks(T0, "critical", 14, "Exfiltration", "data_exfiltration", "malicious", now=T0)
    dora = next(c for c in result["clocks"] if c["regime_id"] == "dora")
    assert dora["deadline"] == (T0 + timedelta(hours=4)).isoformat()
    assert dora["seconds_remaining"] == pytest.approx(4 * 3600, abs=2)


def test_state_transitions_with_elapsed_time():
    args = (T0, "critical", 14, "Exfiltration", "data_exfiltration", "malicious")

    fresh = build_clocks(*args, now=T0)
    assert next(c for c in fresh["clocks"] if c["regime_id"] == "dora")["state"] == "on_track"

    # 3h30m into a 4h window is inside the last quarter.
    late = build_clocks(*args, now=T0 + timedelta(hours=3, minutes=30))
    assert next(c for c in late["clocks"] if c["regime_id"] == "dora")["state"] == "due_soon"

    blown = build_clocks(*args, now=T0 + timedelta(hours=5))
    dora = next(c for c in blown["clocks"] if c["regime_id"] == "dora")
    assert dora["state"] == "overdue"
    assert dora["seconds_remaining"] < 0


def test_non_reportable_produces_no_clocks_but_keeps_the_reason():
    result = build_clocks(T0, "medium", 1, "Reconnaissance", "port_scan", "suspicious", now=T0)
    assert result["reportable"] is False
    assert result["clocks"] == []
    assert result["tightest"] is None
    assert result["reasons"]


def test_regime_selection_is_honoured():
    """A bank subject to one regime should not see three irrelevant countdowns."""
    result = build_clocks(
        T0, "critical", 14, "Exfiltration", "data_exfiltration", "malicious",
        regime_ids=["cert_in"], now=T0,
    )
    assert [c["regime_id"] for c in result["clocks"]] == ["cert_in"]


def test_every_result_carries_the_disclaimer():
    """This is decision support; it must never read as a compliance filing."""
    for args in [
        (T0, "critical", 14, "Exfiltration", "data_exfiltration", "malicious"),
        (T0, "medium", 1, "Reconnaissance", "port_scan", "suspicious"),
    ]:
        result = build_clocks(*args, now=T0)
        assert "not a compliance filing" in result["disclaimer"].lower()
        assert "legal advice" in result["disclaimer"].lower()


def test_missing_or_malformed_timestamp_falls_back_to_now():
    for bad in (None, "", "not-a-date"):
        result = build_clocks(bad, "critical", 14, "Exfiltration", "data_exfiltration", "malicious")
        assert result["determined_at"]


def test_for_campaign_reads_campaign_shape():
    campaign = {
        "campaign_id": "CMP-001",
        "severity": "critical",
        "furthest_stage": "Exfiltration",
        "furthest_stage_order": 14,
        "determined_at": T0.isoformat(),
    }
    result = for_campaign(campaign, now=T0)
    assert result["reportable"] is True
    assert result["tightest"]["regime_id"] == "dora"


# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "seconds,expected",
    [
        (4 * 3600, "4h 0m"),
        (90 * 60, "1h 30m"),
        (45 * 60, "45m"),
        (36 * 3600, "1d 12h"),
        (-2 * 3600 - 240, "overdue by 2h 4m"),
    ],
)
def test_format_remaining(seconds, expected):
    assert format_remaining(seconds) == expected


# ─────────────────────────────────────────────────────────────────────────────
# Citation accuracy
#
# Every one of these was wrong or imprecise until a research pass checked the
# instruments against their primary texts. A deadline asserted with the wrong
# authority is worse than no deadline: it is checkable in thirty seconds and it
# discredits the rest of the assessment.
# ─────────────────────────────────────────────────────────────────────────────

def test_dora_cites_the_delegated_regulation_not_dora_itself():
    """
    Regulation 2022/2554 Art. 19(4) delegates the timings and states no hour
    figure. The 4 hours is in Commission Delegated Regulation (EU) 2025/301.
    """
    dora = next(r for r in REGIMES if r["id"] == "dora")
    assert "2025/301" in dora["instrument"]
    assert "19(4)" in dora["instrument"], "name the delegating article too"


def test_dora_is_described_as_a_hybrid_clock():
    """4 hours from classification AND 24 hours from awareness — not one or the other."""
    note = next(r for r in REGIMES if r["id"] == "dora")["note"].lower()
    assert "24 hours" in note and "aware" in note
    assert "hybrid" in note


def test_dora_records_that_banks_get_no_weekend_relief():
    """
    Art. 5(4) allows a weekend deadline to slip to the next working day; Art. 5(5)
    disapplies that for credit institutions. Stating the general rule without the
    carve-out would tell a bank it has time it does not have.
    """
    note = next(r for r in REGIMES if r["id"] == "dora")["note"].lower()
    assert "credit institution" in note
    assert "no weekend relief" in note


def test_the_us_banking_rule_is_cited_by_codified_section():
    """
    The joint rule is usually given as 86 FR 66424, but 12 CFR Part 53's own
    source note reads 86 FR 66442, so the Federal Register cite sends a reader to
    a different page than intended. The CFR sections are unambiguous.
    """
    rule = next(r for r in REGIMES if r["id"] == "us_banking")
    for section in ("12 CFR 53.3", "12 CFR 225.302", "12 CFR 304.23"):
        assert section in rule["instrument"], section
    assert "66424" not in rule["instrument"]


def test_cert_in_records_the_wider_trigger():
    """
    'Within 6 hours of noticing such incidents or being brought to notice' — a
    third-party report starts the clock — and Annexure I's first reportable item
    is targeted scanning, so no compromise is required.
    """
    cert = next(r for r in REGIMES if r["id"] == "cert_in")
    assert "brought to notice" in cert["starts_from"]
    assert "scanning" in cert["note"].lower()


def test_sec_records_determination_not_discovery_and_the_rescission_petition():
    sec = next(r for r in REGIMES if r["id"] == "sec_8k")
    note = sec["note"].lower()
    assert "determination" in note and "not from discovery" in note
    assert "rescission" in note, "Item 1.05 is under an active petition; say so"


def test_every_regime_still_carries_a_resolvable_instrument_and_url():
    for regime in REGIMES:
        assert regime["instrument"] and regime["url"].startswith("https://")
        assert regime["effective"], regime["id"]


def test_dora_records_that_the_later_deadlines_chain(monkeypatch):
    """
    The 72 hours runs from submission of the initial notification and the month
    from the intermediate report, not all four from one origin. A timeline drawing
    them off a single t=0 is wrong, and that is the natural way to draw it.
    """
    note = next(r for r in REGIMES if r["id"] == "dora")["note"]
    assert "72 hours of submitting the INITIAL NOTIFICATION" in note
    assert "one month of the intermediate" in note
    assert "2024/1772" in note, "name the instrument that defines 'major'"


def test_dora_does_not_overstate_the_weekend_carve_out():
    """
    Art. 5(5) disapplies the extension for the initial notification and the
    intermediate report only. A credit institution keeps it for the final report,
    and claiming otherwise is checkable in one reading.
    """
    note = next(r for r in REGIMES if r["id"] == "dora")["note"]
    assert "keeps the extension for the final report" in note


def test_cert_in_states_the_exact_category_count():
    note = next(r for r in REGIMES if r["id"] == "cert_in")["note"]
    assert "exactly 20 categories" in note
    assert "FAQ" in note, "the severity gate is not in the Direction text; say so"


def test_a_determination_survives_a_re_run(tmp_path, monkeypatch):
    """
    Regulatory clocks run from determination, so the determination time is a fact
    about the past. It was recomputed as now() on every pipeline pass, which meant
    re-processing the same logs silently reset every deadline to a full window —
    the one thing a notification clock must never do, because it hides a deadline
    that has already been missed.
    """
    import db_manager

    monkeypatch.setattr(db_manager, "DB_PATH", tmp_path / "t.db", raising=False)
    monkeypatch.setattr(db_manager, "DB_FILE", str(tmp_path / "t.db"), raising=False)
    db_manager.init_db()
    db_manager.clear_determinations()

    first = db_manager.determination_time("campaign:abc", "2026-08-22T09:00:00+00:00")
    again = db_manager.determination_time("campaign:abc", "2026-08-22T17:30:00+00:00")
    assert first == again == "2026-08-22T09:00:00+00:00", (
        "a second look-up must return the original determination, not the new proposal"
    )

    # A different subject gets its own clock.
    other = db_manager.determination_time("campaign:def", "2026-08-22T17:30:00+00:00")
    assert other == "2026-08-22T17:30:00+00:00"
