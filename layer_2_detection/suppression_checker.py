"""
suppression_checker.py
Layer 2 Suppression Hook

Queries the analyst_feedback table for all False Positive labels and
builds a set of suppression rules. When an event matches a rule, the
detection pipeline short-circuits it as 'suppressed' instead of running
all engines.

This is how FP feedback actually affects future pipeline runs.
"""

import os
import sys

# Ensure the project root is on the path so we can import db_manager
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def load_suppression_rules() -> list[dict]:
    """
    Load all False Positive suppression rules from the database.
    Returns a list of rule dicts with keys: source_ip, threat_type, affected_user.
    Gracefully returns [] if the database isn't available (e.g. on first run before DB init).
    """
    try:
        from db_manager import get_suppression_list
        return get_suppression_list()
    except Exception as e:
        print(f"[suppression_checker] Warning: could not load suppression rules: {e}")
        return []


def is_suppressed(event: dict, suppression_rules: list[dict] | None = None) -> tuple[bool, str]:
    """
    Check if an event matches any known False Positive suppression rule.

    Matching logic (any of the following triggers suppression):
      1. Exact source_ip match (if rule.source_ip is not None)
      2. Exact threat_type match (if rule.threat_type is not None) — applied only if
         the event's raw source_ip is not in the rule (avoid over-suppression)
      3. Exact affected_user + threat_type combo match

    Returns:
        (True, reason_string)  — if event is suppressed
        (False, "")            — if event should proceed normally
    """
    if suppression_rules is None:
        suppression_rules = load_suppression_rules()

    if not suppression_rules:
        return False, ""

    # Extract event features for matching
    dashboard  = event.get("dashboard") or {}
    detection  = event.get("detection") or {}
    raw_event  = event.get("raw_event") or {}

    event_source_ip   = (
        dashboard.get("source_ip")
        or raw_event.get("source_ip")
        or event.get("source_ip", "")
    )
    event_threat_type = (
        detection.get("threat_type")
        or event.get("threat_type", "")
    )
    event_user        = (
        dashboard.get("affected_user")
        or raw_event.get("user")
        or raw_event.get("affected_user", "")
    )

    for rule in suppression_rules:
        rule_ip   = rule.get("source_ip")
        rule_tt   = rule.get("threat_type")
        rule_user = rule.get("affected_user")

        # Rule 1: Source IP exact match
        if rule_ip and event_source_ip and rule_ip == event_source_ip:
            return True, f"Source IP {event_source_ip} is on the False Positive suppression list."

        # Rule 2: Threat type + user combo match
        if (
            rule_tt and rule_user and event_threat_type and event_user
            and rule_tt == event_threat_type and rule_user == event_user
        ):
            return True, (
                f"Threat pattern '{event_threat_type}' for user '{event_user}' "
                "matches a known False Positive suppression rule."
            )

        # Rule 3: Threat type only (if IP doesn't match — avoid broad suppression)
        if (
            rule_tt and event_threat_type and not rule_ip and not rule_user
            and rule_tt == event_threat_type
        ):
            return True, (
                f"Threat type '{event_threat_type}' is globally suppressed "
                "based on analyst feedback."
            )

    return False, ""


def build_suppressed_detection(event: dict, reason: str) -> dict:
    """
    Build a short-circuit detection result for suppressed events.
    Marks the event as 'suppressed' with minimal severity.
    """
    event["detection"] = {
        "label":            "suppressed",
        "threat_type":      event.get("detection", {}).get("threat_type", "unknown"),
        "severity":         "low",
        "confidence":       0.0,
        "triggered_engines": [],
        "reasoning":        [f"[SUPPRESSED] {reason}"],
        "suppressed":       True,
    }
    return event
