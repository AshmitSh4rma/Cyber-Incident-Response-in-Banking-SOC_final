"""
Layer 2 smoke test.

Feeds a hand-built brute-force event straight into the detection orchestrator and
asserts the engines actually reach a verdict. This was previously an ad-hoc
script with module-level code, so pytest crashed on collection.
"""

from layer_2_detection.detection_orchestrator import run_detection


def _brute_force_event() -> dict:
    return {
        "event_id": "evt_001",
        "log_type": "auth",
        "action": "login_failed",
        "source_ip": "203.0.113.45",
        "temporal_features": {"is_off_hours": True},
        "behavioral_features": {
            "failed_login_count": 7,
            "rare_source_ip": True,
            "is_new_ip_for_user": True,
        },
        "statistical_features": {"z_score": 2.9},
        "identity_features": {"is_signin_activity": True, "is_failed_login": True},
    }


def test_brute_force_is_detected():
    result = run_detection(_brute_force_event(), suppression_rules=[])
    detection = result["detection"]

    assert detection["label"] in {"suspicious", "malicious"}
    assert detection["threat_type"] != "unknown"
    assert 0.0 < detection["confidence"] <= 1.0
    assert detection["severity"] in {"low", "medium", "high", "critical"}
    assert detection["triggered_engines"], "no engine reported a signal"
    assert detection["reasoning"], "no reasoning produced for the analyst"


def test_brute_force_names_the_pattern():
    result = run_detection(_brute_force_event(), suppression_rules=[])
    assert result["detection"]["threat_type"] == "brute_force_attempt"


def test_suppression_rule_short_circuits_detection():
    rules = [{"source_ip": "203.0.113.45", "threat_type": None, "affected_user": None}]
    result = run_detection(_brute_force_event(), suppression_rules=rules)

    assert result["detection"]["suppressed"] is True
    assert result["detection"]["label"] == "suppressed"
    assert result["detection"]["triggered_engines"] == []


def test_benign_event_is_not_flagged_malicious():
    benign = {
        "event_id": "evt_benign",
        "log_type": "network",
        "action": "allow",
        "source_ip": "10.0.0.9",
        "temporal_features": {"is_off_hours": False},
        "behavioral_features": {},
        "statistical_features": {},
    }
    result = run_detection(benign, suppression_rules=[])
    assert result["detection"]["label"] != "malicious"
