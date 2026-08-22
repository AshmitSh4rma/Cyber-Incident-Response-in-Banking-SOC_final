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
