"""
Tests for runtime configuration.

Two things are being protected here, and they are not the same thing.

The first is that a setting *works*: change it and the pipeline's behaviour
changes, without a restart. A settings screen whose controls do nothing is worse
than no settings screen, because the operator believes them.

The second is that a bad setting is *refused whole*. Configuration is the one
place where a half-applied change is plausible and disastrous: the operator sees
the state they asked for, and the system is in a different one.
"""

import json
import pathlib

import pytest

import soc_config
from layer_2_detection.campaign_correlator import correlate_campaigns
from layer_2_detection.detection_fusion import fuse_detection
from layer_6_response.response_orchestrator import run_response
from regulatory_clock import REGIMES, build_clocks
from soc_metrics import compute_metrics


@pytest.fixture(autouse=True)
def clean_config(tmp_path, monkeypatch):
    """
    Every test starts from shipped defaults and writes to a throwaway file.

    Pointed at tmp_path rather than the repo so a failing test cannot leave the
    developer's own configuration changed — the module writes to disk by design.
    """
    monkeypatch.setattr(soc_config, "CONFIG_PATH", tmp_path / "soc_config.json")
    monkeypatch.setattr(soc_config, "AUDIT_PATH", tmp_path / "soc_config_audit.json")
    soc_config.invalidate()
    yield
    soc_config.invalidate()


# ─────────────────────────────────────────────────────────────────────────────
# The schema has to be self-describing, because the console renders from it
# ─────────────────────────────────────────────────────────────────────────────

def test_every_setting_is_renderable_without_reading_the_source():
    for spec in soc_config.SETTINGS:
        assert spec["key"] and spec["group"] and spec["label"], spec
        assert spec["affects"], f"{spec['key']} does not say what it changes"
        assert spec["type"] in ("int", "float", "bool", "choice", "multi")
        if spec["type"] in ("int", "float"):
            assert spec["min"] < spec["max"]
            assert spec["min"] <= spec["default"] <= spec["max"]
        if spec["type"] in ("choice", "multi"):
            allowed = [o[0] for o in spec["options"]]
            assert allowed, f"{spec['key']} has no options"
            chosen = spec["default"] if spec["type"] == "multi" else [spec["default"]]
            assert all(v in allowed for v in chosen)


def test_every_group_has_settings_and_every_setting_a_group():
    group_ids = {g["id"] for g in soc_config.GROUPS}
    used = {s["group"] for s in soc_config.SETTINGS}
    assert used <= group_ids, f"settings in undeclared groups: {used - group_ids}"
    assert group_ids <= used, f"groups with no settings: {group_ids - used}"


def test_demo_values_actually_differ_from_defaults():
    """A 'try this' button that sets the current value teaches nothing."""
    for spec in soc_config.SETTINGS:
        if spec.get("demo") is None:
            continue
        assert spec["demo"] != spec["default"], spec["key"]


def test_regime_options_match_the_regimes_that_exist():
    """
    The options are declared in soc_config rather than imported, to keep every
    layer's config import free of pipeline imports. That is only safe with a test
    holding the two lists together.
    """
    assert [o[0] for o in soc_config.REGIME_OPTIONS] == [r["id"] for r in REGIMES]


def test_kill_chain_options_match_the_attack_matrix():
    from layer_2_detection.mitre_mapper import TACTICS

    orders = {str(t["order"]): t["name"] for t in TACTICS}
    for value, label in soc_config.KILL_CHAIN_STAGES:
        assert value in orders, f"stage order {value} is not in the ATT&CK matrix"
        assert orders[value] == label, f"stage {value} is {orders[value]}, not {label}"


# ─────────────────────────────────────────────────────────────────────────────
# Reading and writing
# ─────────────────────────────────────────────────────────────────────────────

def test_defaults_apply_with_no_file_present():
    assert soc_config.modified_keys() == []
    assert soc_config.status()["is_default"] is True
    assert soc_config.get("detection.brute_force_attempts") == 3


def test_a_saved_value_is_visible_immediately():
    soc_config.save({"detection.brute_force_attempts": 9})
    assert soc_config.get("detection.brute_force_attempts") == 9
    assert soc_config.modified_keys() == ["detection.brute_force_attempts"]


def test_only_differences_from_default_are_stored():
    soc_config.save({"detection.brute_force_attempts": 9})
    stored = json.loads(soc_config.CONFIG_PATH.read_text())
    assert stored["values"] == {"detection.brute_force_attempts": 9}

    # Returning a setting to its default removes it rather than pinning it, so
    # the file stays a record of genuine differences.
    soc_config.save({"detection.brute_force_attempts": 3})
    assert json.loads(soc_config.CONFIG_PATH.read_text())["values"] == {}
    assert soc_config.modified_keys() == []


def test_reset_restores_every_default():
    soc_config.save({"detection.brute_force_attempts": 9, "reporting.min_severity": "critical"})
    result = soc_config.reset()
    assert len(result["changes"]) == 2
    assert soc_config.modified_keys() == []


def test_a_change_is_recorded_with_what_it_was():
    soc_config.save({"reporting.min_severity": "critical"}, actor="tester")
    entry = soc_config.audit()[0]
    assert entry["actor"] == "tester"
    assert entry["changes"][0] == {
        "key": "reporting.min_severity",
        "label": soc_config.SETTINGS_BY_KEY["reporting.min_severity"]["label"],
        "from": "high",
        "to": "critical",
    }


def test_a_corrupt_file_falls_back_to_defaults_rather_than_crashing():
    soc_config.CONFIG_PATH.write_text("{ this is not json")
    soc_config.invalidate()
    assert soc_config.get("detection.brute_force_attempts") == 3
    # And says so, so the console can warn instead of silently misreporting.
    assert soc_config.status()["stored_file_readable"] is False


def test_a_setting_removed_from_the_schema_is_ignored():
    soc_config.CONFIG_PATH.write_text(json.dumps({"values": {"gone.away": 1, "reporting.min_severity": "low"}}))
    soc_config.invalidate()
    assert soc_config.get("reporting.min_severity") == "low"
    assert "gone.away" not in soc_config.values()


def test_a_file_edited_on_disk_is_picked_up_without_a_restart():
    """
    The API server and the offline runner are separate processes writing and
    reading the same file, so a cached read that never re-checks would leave one
    of them permanently stale.
    """
    assert soc_config.get("detection.brute_force_attempts") == 3
    soc_config.CONFIG_PATH.write_text(
        json.dumps({"values": {"detection.brute_force_attempts": 7}})
    )
    assert soc_config.get("detection.brute_force_attempts") == 7


# ─────────────────────────────────────────────────────────────────────────────
# Validation — the part that has to refuse things
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("patch", [
    {"detection.brute_force_attempts": 0},          # below the floor
    {"detection.brute_force_attempts": 500},        # above the ceiling
    {"detection.brute_force_attempts": "many"},     # not a number
    {"detection.brute_force_attempts": True},       # a bool is not a count
    {"severity.port_scan": "catastrophic"},         # not a severity
    {"reporting.regimes": ["atlantis"]},            # not a regime
    {"reporting.regimes": []},                      # below min_selected
    {"reporting.regimes": "dora"},                  # not a list
    {"reporting.require_foothold": "maybe"},        # not a boolean
    {"nonexistent.setting": 1},                     # not a setting
])
def test_bad_values_are_rejected(patch):
    _, errors = soc_config.validate(patch)
    assert errors, f"expected {patch} to be rejected"


def test_nothing_is_written_when_any_part_of_a_patch_is_invalid():
    """The rule that matters: applied whole, or not at all."""
    with pytest.raises(ValueError):
        soc_config.save({
            "detection.brute_force_attempts": 9,   # fine on its own
            "severity.port_scan": "catastrophic",  # not
        })
    assert soc_config.get("detection.brute_force_attempts") == 3
    assert not soc_config.CONFIG_PATH.exists()


def test_every_problem_is_reported_not_just_the_first():
    _, errors = soc_config.validate({
        "detection.brute_force_attempts": 0,
        "severity.port_scan": "catastrophic",
        "reporting.regimes": [],
    })
    assert len(errors) == 3


def test_a_confidence_ceiling_below_the_malicious_threshold_is_refused():
    """
    Without this the operator can silently remove the 'malicious' verdict from
    the whole system: the ceiling caps confidence below the value the verdict
    requires, so nothing can ever reach it again.
    """
    _, errors = soc_config.validate({"detection.confidence_cap": 0.70})
    assert "detection.confidence_cap" in errors
    _, errors = soc_config.validate({"detection.confidence_cap": 0.99})
    assert not errors


def test_review_time_cannot_equal_or_exceed_manual_time():
    """Otherwise the dashboard claims the system costs time and calls it a saving."""
    _, errors = soc_config.validate({"model.review_minutes_per_incident": 15.0})
    assert "model.review_minutes_per_incident" in errors


def test_cross_field_rules_are_checked_against_the_stored_other_half():
    """Changing one side of a pair must be caught against the saved other side."""
    soc_config.save({"model.review_minutes_per_incident": 10.0})
    _, errors = soc_config.validate({"model.manual_minutes_per_alert": 8.0})
    assert errors, "lowering the manual figure under the stored review figure must fail"


def test_duplicate_selections_are_collapsed():
    cleaned, errors = soc_config.validate({"reporting.regimes": ["dora", "dora", "cert_in"]})
    assert not errors
    assert cleaned["reporting.regimes"] == ["dora", "cert_in"]


# ─────────────────────────────────────────────────────────────────────────────
# Does the setting actually reach the pipeline?
#
# The whole feature rests on this. Each of these changes one setting and asserts
# a different observable output, in the same process, with no reload.
# ─────────────────────────────────────────────────────────────────────────────

def _detection_event(threat="port_scan", anomaly=0.9, confidence=0.5):
    return {
        "anomaly_detection": {"anomaly_score": anomaly},
        "threat_analysis": {"mapped_pattern": threat},
        "correlation_analysis": {"adjusted_confidence": confidence, "correlation_strength": "weak"},
    }


def test_severity_policy_reaches_the_verdict():
    assert fuse_detection(_detection_event())["detection"]["severity"] == "medium"
    soc_config.save({"severity.port_scan": "critical"})
    assert fuse_detection(_detection_event())["detection"]["severity"] == "critical"


def test_the_suspicious_floor_reaches_the_label():
    quiet = _detection_event(threat="unknown", anomaly=0.45, confidence=0.0)
    assert fuse_detection(quiet)["detection"]["label"] == "benign"
    soc_config.save({"detection.suspicious_score_floor": 0.30})
    assert fuse_detection(quiet)["detection"]["label"] == "suspicious"


def test_the_regime_selection_reaches_the_clocks():
    args = ("2026-08-22T08:00:00+00:00", "critical", 14, "Exfiltration", "data_exfiltration", "malicious")
    assert len(build_clocks(*args)["clocks"]) == 4
    soc_config.save({"reporting.regimes": ["cert_in"]})
    clocks = build_clocks(*args)["clocks"]
    assert [c["regime_id"] for c in clocks] == ["cert_in"]


def test_the_reporting_threshold_reaches_reportability():
    # A medium-severity foothold is not reportable by default.
    args = ("2026-08-22T08:00:00+00:00", "medium", 3, "Initial Access", "web_attack", "malicious")
    assert build_clocks(*args)["reportable"] is False
    soc_config.save({"reporting.min_severity": "medium"})
    assert build_clocks(*args)["reportable"] is True


def test_turning_off_the_foothold_requirement_reaches_reportability():
    args = ("2026-08-22T08:00:00+00:00", "critical", 1, "Reconnaissance", "port_scan", "malicious")
    assert build_clocks(*args)["reportable"] is False
    soc_config.save({"reporting.require_foothold": False})
    assert build_clocks(*args)["reportable"] is True


def test_the_savings_model_reaches_the_metrics():
    incidents = [
        {"detection": {"label": "malicious", "severity": "high"}} for _ in range(10)
    ]
    baseline = compute_metrics(incidents, [])["time"]["hours_saved"]
    soc_config.save({"model.manual_minutes_per_alert": 30.0})
    assert compute_metrics(incidents, [])["time"]["hours_saved"] > baseline


def test_withholding_a_response_category_reaches_the_approval_gate():
    event = {
        "raw_event": {"affected_host": "ssh-bastion-01"},
        "dashboard": {"affected_host": "ssh-bastion-01"},
        "detection": {"threat_type": "brute_force_attempt", "severity": "high", "label": "malicious"},
    }

    def blocking_steps():
        plan = run_response(event)["containment_plan"]
        return [s for s in plan if s["action"].lower().startswith("block")]

    assert blocking_steps(), "expected a blocking step in the brute-force playbook"
    assert all(s["execution"] == "auto" for s in blocking_steps())

    soc_config.save({"response.automatic_actions": ["enrich", "notify", "monitor"]})
    assert all(s["execution"] == "requires_approval" for s in blocking_steps())


def test_withholding_a_category_never_downgrades_the_blast_radius_gate():
    """
    Permission is one-directional. Ticking a box may not override the gate on
    service-affecting actions, because that gate is about damage, not consent.
    """
    soc_config.save({
        "response.automatic_actions": [a[0] for a in soc_config.RESPONSE_ACTIONS],
    })
    event = {
        "raw_event": {"affected_host": "db-core-01"},
        "dashboard": {"affected_host": "db-core-01"},
        "detection": {"threat_type": "lateral_movement", "severity": "critical", "label": "malicious"},
    }
    result = run_response(event)
    isolating = [s for s in result["containment_plan"] if "isolate" in s["action"].lower()]
    assert isolating
    assert all(s["execution"] == "requires_approval" for s in isolating)
    assert all(s["blast_radius"] == "service-affecting" for s in isolating)


def _chain_incident(event_id, ts, src, host, threat, stage_order, stage):
    return {
        "event_id": event_id,
        "raw_event": {"timestamp": ts, "source_ip": src, "affected_host": host,
                      "destination_ip": "", "affected_user": ""},
        "dashboard": {"source_ip": src, "affected_host": host, "destination_ip": "",
                      "affected_user": ""},
        "detection": {"threat_type": threat, "severity": "high", "confidence": 0.9,
                      "label": "malicious"},
        "mitre_attack": {"kill_chain_stage": stage, "kill_chain_order": stage_order,
                         "primary": {"technique_id": "T9999", "technique_name": "Test"}},
    }


def test_the_compromise_gate_reaches_campaign_correlation():
    """
    A scan reaching a host does not make that host the attacker's — unless the
    institution says the bar is that low. Both answers must be reachable.
    """
    events = [
        _chain_incident("scan", "2026-01-01T00:00:00Z", "10.99.0.5", "core-app",
                        "port_scan", 1, "Reconnaissance"),
        _chain_incident("later", "2026-01-01T05:00:00Z", "core-app", "db-01",
                        "lateral_movement", 11, "Lateral Movement"),
    ]
    assert correlate_campaigns(events)["campaigns"] == []

    soc_config.save({"detection.campaign_min_stage": "1"})
    assert len(correlate_campaigns(events)["campaigns"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Preview
# ─────────────────────────────────────────────────────────────────────────────

def test_previewing_does_not_write_anything():
    with soc_config.previewing({"detection.brute_force_attempts": 42}):
        assert soc_config.get("detection.brute_force_attempts") == 42
        assert soc_config.values()["detection.brute_force_attempts"] == 42
    assert soc_config.get("detection.brute_force_attempts") == 3
    assert not soc_config.CONFIG_PATH.exists()


def test_a_preview_reaches_the_pipeline_and_is_then_withdrawn():
    quiet = _detection_event(threat="unknown", anomaly=0.45, confidence=0.0)
    assert fuse_detection(quiet)["detection"]["label"] == "benign"
    with soc_config.previewing({"detection.suspicious_score_floor": 0.30}):
        assert fuse_detection(quiet)["detection"]["label"] == "suspicious"
    assert fuse_detection(quiet)["detection"]["label"] == "benign"


def test_a_preview_leaves_saved_settings_intact_underneath():
    soc_config.save({"detection.brute_force_attempts": 9})
    with soc_config.previewing({"detection.exfil_ratio": 50.0}):
        # The previewed key is overridden; the saved one still shows through.
        assert soc_config.get("detection.exfil_ratio") == 50.0
        assert soc_config.get("detection.brute_force_attempts") == 9
    assert soc_config.get("detection.exfil_ratio") == 10.0
    assert soc_config.get("detection.brute_force_attempts") == 9


def test_a_failing_preview_still_withdraws_the_override():
    with pytest.raises(RuntimeError):  # noqa: PT012 — the raise is the point
        with soc_config.previewing({"detection.brute_force_attempts": 42}):
            raise RuntimeError("pipeline blew up mid-preview")
    assert soc_config.get("detection.brute_force_attempts") == 3


# ─────────────────────────────────────────────────────────────────────────────
# Nothing decorative
# ─────────────────────────────────────────────────────────────────────────────

def test_every_setting_is_read_by_something():
    """
    A setting the console renders and nothing consumes is the worst defect this
    feature can have: the operator moves a control, the system does not change,
    and they have no way to tell. The behavioural tests above cover the settings
    with an easy observable; this is the backstop for the rest, and for anything
    added later. It caught response.gate_above_hosts, which was declared and
    never wired.

    Views settings are read by the frontend, so the sweep includes TypeScript.
    """
    import subprocess

    root = pathlib.Path(soc_config.__file__).resolve().parent
    consumers = subprocess.run(
        ["grep", "-rIl", "--include=*.py", "--include=*.ts", "--include=*.tsx",
         "--exclude-dir=node_modules", "--exclude-dir=.next", "--exclude-dir=.git",
         "-e", "soc_config", "-e", "views.", str(root)],
        capture_output=True, text=True, check=False,
    ).stdout.splitlines()

    haystack = "\n".join(
        pathlib.Path(f).read_text(encoding="utf-8", errors="ignore")
        for f in consumers
        if "soc_config.py" not in f and "test_config.py" not in f
    )

    # The severity family is resolved from the threat type at runtime
    # (f"severity.{threat_type}"), so no literal key appears anywhere to grep for.
    # That mechanism is asserted directly by test_severity_policy_reaches_the_verdict,
    # and the keys themselves by the next test.
    assert 'f"severity.{threat_type}"' in haystack, (
        "the dynamic severity lookup is gone; this exemption is no longer valid"
    )

    orphans = [
        s["key"] for s in soc_config.SETTINGS
        if not s["key"].startswith("severity.") and s["key"] not in haystack
    ]
    assert not orphans, (
        "these settings are rendered but read by nothing, so moving them does "
        f"nothing: {orphans}"
    )


def test_every_severity_setting_names_a_threat_the_system_can_emit():
    """
    The severity family is only reachable for threat types the classifier can
    actually produce. A key for anything else is a control that will never fire,
    and the dynamic lookup means nothing would ever report it.
    """
    from layer_2_detection.engine_2_threat_analysis.threat_classifier import (
        PATTERN_PRIORITY,
    )

    configured = [
        s["key"].removeprefix("severity.")
        for s in soc_config.SETTINGS
        if s["key"].startswith("severity.")
    ]
    unreachable = [t for t in configured if t not in PATTERN_PRIORITY]
    assert not unreachable, f"no threat pattern ever produces: {unreachable}"


def test_the_blast_radius_limit_reaches_the_approval_gate():
    """
    A disruptive action against a host that is one of several the same intruder
    owns is not a one-host decision. This was the orphan the sweep above found.
    """
    event = {
        "raw_event": {"affected_host": "app-01"},
        "dashboard": {"affected_host": "app-01"},
        "detection": {"threat_type": "lateral_movement", "severity": "critical", "label": "malicious"},
        "campaign": {"asset_count": 6},
    }

    def disruptive_steps():
        plan = run_response(event)["containment_plan"]
        return [s for s in plan if s["blast_radius"] != "contained"]

    # Six hosts is over the default limit of one, so the wide action waits.
    assert any(s["execution"] == "requires_approval" for s in disruptive_steps())
    assert any(s["blast_radius"] == "multi-host" for s in disruptive_steps())

    # Raise the limit past the campaign's footprint and the blast-radius gate on
    # scope no longer applies.
    soc_config.save({"response.gate_above_hosts": 20})
    assert not any(s["blast_radius"] == "multi-host" for s in disruptive_steps())


def test_a_single_alert_is_never_treated_as_a_wide_action():
    """An incident with no campaign is one host, not zero and not many."""
    event = {
        "raw_event": {"affected_host": "app-01"},
        "dashboard": {"affected_host": "app-01"},
        "detection": {"threat_type": "lateral_movement", "severity": "critical", "label": "malicious"},
        "campaign": None,
    }
    plan = run_response(event)["containment_plan"]
    assert not any(s["blast_radius"] == "multi-host" for s in plan)
