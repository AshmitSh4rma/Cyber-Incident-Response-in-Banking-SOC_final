"""
Tests for Layer 3 control mapping.

Every case here is a mapping that was wrong before, and each was wrong in a way
that a demo would have shown to a judge as a confident, cited answer. That is
the failure mode worth guarding: not a crash, but a plausible citation of the
wrong control.
"""

import pytest

from layer_3_cis.benchmark_matcher import _keyword_weights, retrieve_benchmarks
from layer_3_cis.engines.iot_engine import process_iot_event
from layer_3_cis.engines.web_engine import process_web_event
from layer_3_cis.router import route_entry


def _event(log_type, *, url="", method="", protocol="", port=None,
           threat_type="web_attack", label="malicious", technique="", technique_name=""):
    return {
        "log_type": log_type,
        "raw_event": {
            "log_type": log_type,
            "url": url,
            "http_method": method,
            "protocol": protocol,
            "port": port,
            "affected_host": "test-host-01",
        },
        "detection": {"threat_type": threat_type, "label": label},
        "engine_2_threat_intel": {
            "mitre_technique": technique,
            "mitre_technique_name": technique_name,
        },
    }


def _control(enriched):
    matched = enriched["cis_benchmark"]["matched_benchmarks"]
    return matched[0] if matched else None


# ─────────────────────────────────────────────────────────────────────────────
# Keyword weighting
# ─────────────────────────────────────────────────────────────────────────────

def test_rare_keywords_outweigh_common_ones():
    """
    The CIS network catalogue is 413 Cisco controls in which "management" and
    "configured" are near-ubiquitous. With flat weights they outvoted the one
    term that identified the finding.
    """
    weights = _keyword_weights("network")
    assert weights, "expected a populated weight table for the network catalogue"
    assert weights["telnet"] > weights["management"]


def test_weights_are_clamped_at_both_ends():
    weights = _keyword_weights("network")
    assert all(0.5 <= w <= 3.0 for w in weights.values())


def test_unknown_domain_has_no_weights():
    assert _keyword_weights("no-such-domain") == {}


# ─────────────────────────────────────────────────────────────────────────────
# Web / OWASP
# ─────────────────────────────────────────────────────────────────────────────

def test_sql_injection_maps_to_a03_injection():
    """
    ATT&CK calls this T1190 "Exploit Public-Facing Application" — too coarse to
    pick an OWASP category from, so the payload has to be read. Before that, the
    query carried nothing but generic tags and every web event came back as
    "A04 Insecure Design".
    """
    enriched = process_web_event(
        _event("web", url="/retail/login?user=admin' OR '1'='1--", method="POST",
               technique="T1190", technique_name="Exploit Public-Facing Application")
    )
    assert _control(enriched)["benchmark_id"] == "OWASP-A03"


@pytest.mark.parametrize("url", [
    "/accounts?id=1 UNION SELECT card_number,cvv FROM cards",
    "/search?q=<script>alert(document.cookie)</script>",
    "/api/run?cmd=id",
])
def test_injection_family_payloads_map_to_a03(url):
    assert _control(process_web_event(_event("web", url=url)))["benchmark_id"] == "OWASP-A03"


def test_path_traversal_is_an_access_control_failure_not_an_injection():
    enriched = process_web_event(_event("web", url="/download?file=../../../../etc/passwd"))
    assert _control(enriched)["benchmark_id"] == "OWASP-A01"


def test_encoded_traversal_is_decoded_before_matching():
    enriched = process_web_event(_event("web", url="/download?file=%2e%2e%2f%2e%2e%2fetc/passwd"))
    assert _control(enriched)["benchmark_id"] == "OWASP-A01"


def test_web_shell_upload_maps_to_a04_per_cwe_434():
    """
    CWE-434 "Unrestricted Upload of File with Dangerous Type" sits in the
    A04:2021 category (CWE-1348). A04 is also what the broken version returned
    for everything, so this asserts the *query* is specific, not just the answer.
    """
    enriched = process_web_event(_event("web", url="/admin/upload.php", method="POST"))
    assert _control(enriched)["benchmark_id"] == "OWASP-A04"
    query = enriched["cis_benchmark"]["retrieval_query"]
    assert "secure_design" in query["query_tags"]
    assert "web_application" not in query["query_tags"], "generic tags bias every result"


def test_reading_an_ordinary_php_page_is_not_an_upload_finding():
    """Both halves of CWE-434 are required: dangerous type *and* an upload."""
    enriched = process_web_event(_event("web", url="/shop/index.php", method="GET"))
    control = _control(enriched)
    assert control is None or control["benchmark_id"] != "OWASP-A04"


def test_privileged_path_with_no_payload_is_broken_access_control():
    enriched = process_web_event(_event("web", url="/actuator/env", method="GET"))
    assert _control(enriched)["benchmark_id"] == "OWASP-A01"


def test_generic_web_event_does_not_invent_a_category():
    """A query with nothing specific to say should return nothing."""
    enriched = process_web_event(
        _event("web", url="/retail/accounts/summary", method="GET",
               threat_type="unknown", label="benign")
    )
    assert enriched["cis_benchmark"]["retrieval_query"]["query_tags"] == []
    assert _control(enriched) is None


# ─────────────────────────────────────────────────────────────────────────────
# IoT / OT
# ─────────────────────────────────────────────────────────────────────────────

def test_telnet_device_maps_to_disabling_telnet():
    """
    A branch camera on cleartext Telnet used to be scored against a catalogue of
    iOS and Android privacy settings, so it always fell through to a hardcoded
    fallback.
    """
    enriched = process_iot_event(
        _event("iot", protocol="telnet", port=23, threat_type="credential_abuse",
               technique="T1552")
    )
    control = _control(enriched)
    assert control is not None
    assert "telnet" in control["title"].lower()


def test_iot_events_are_scored_against_network_controls():
    enriched = process_iot_event(_event("iot", protocol="telnet", port=23))
    assert enriched["cis_benchmark"]["framework"] == "network_controls_catalog"


def test_hostname_is_not_used_as_a_search_term():
    """
    A hostname is per-deployment; no benchmark control mentions one. Passing it
    as a keyword contributed nothing and produced a spurious 'no matches' warning.
    """
    enriched = process_iot_event(_event("iot", protocol="telnet", port=23))
    assert "test-host-01" not in enriched["cis_benchmark"]["retrieval_query"]["query_keywords"]


def test_cleartext_is_detected_from_the_port_when_protocol_is_missing():
    enriched = process_iot_event(_event("iot", protocol="", port=21))
    assert "ftp" in enriched["cis_benchmark"]["retrieval_query"]["query_keywords"]


def test_non_numeric_port_does_not_raise():
    event = _event("iot", protocol="telnet")
    event["raw_event"]["port"] = "not-a-port"
    assert process_iot_event(event)["cis_benchmark"]["matched_benchmarks"]


# ─────────────────────────────────────────────────────────────────────────────
# Routing
# ─────────────────────────────────────────────────────────────────────────────

def test_the_deleted_iot_catalogue_is_no_longer_reachable():
    assert retrieve_benchmarks(domain="iot", query_keywords=["telnet"]) == []


def test_unknown_log_type_passes_through_unmapped():
    event = _event("mainframe", threat_type="unknown")
    assert "cis_benchmark" not in route_entry(event)


@pytest.mark.parametrize("threat_type,expected_framework", [
    ("suspicious_login_behavior", "web_owasp_catalog"),
    ("brute_force_attempt", "network_controls_catalog"),
])
def test_auth_events_split_on_threat_type(threat_type, expected_framework):
    event = _event("auth", threat_type=threat_type, protocol="tcp", port=22)
    assert route_entry(event)["cis_benchmark"]["framework"] == expected_framework
