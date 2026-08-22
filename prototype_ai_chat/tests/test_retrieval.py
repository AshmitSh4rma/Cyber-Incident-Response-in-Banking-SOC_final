from __future__ import annotations

from contextlib import contextmanager

import pytest

from prototype_ai_chat import retrieval


def _incident(event_id: str, timestamp: str, severity: str = "high") -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "severity": severity,
        "status": "open",
        "threat_type": "test",
        "source_ip": "192.0.2.1",
        "affected_user": "analyst",
        "affected_host": "host-1",
        "payload": '{"event_id":"' + event_id + '"}',
    }


def _campaign(campaign_id: str) -> dict:
    return {
        "campaign_id": campaign_id,
        "severity": "critical",
        "progression_pct": 90,
        "first_seen": "2026-08-22T00:00:00Z",
        "last_seen": "2026-08-22T01:00:00Z",
        "payload": '{"campaign_id":"' + campaign_id + '"}',
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 10), (2, 2), (100, 100), (1000, 100), (0, 1), ("bad", 10)],
)
def test_limit_bounding(value, expected):
    assert retrieval.bound_limit(value) == expected


def test_payload_parsing():
    assert retrieval.parse_payload('{"ok":true}').value == {"ok": True}
    assert retrieval.parse_payload('{"ok":true}').valid is True
    assert retrieval.parse_payload("").valid is False
    assert retrieval.parse_payload(None).value == {}
    assert retrieval.parse_payload("not-json").valid is False
    assert retrieval.parse_payload("not-json").value == {}


def test_default_and_requested_limits_are_parameterized(monkeypatch):
    calls = []

    def fake(sql, params=()):
        calls.append((sql, params))
        return []

    monkeypatch.setattr(retrieval, "_fetch_all", fake)
    retrieval.get_recent_incidents()
    retrieval.get_recent_incidents(3)
    retrieval.list_campaigns(999)
    assert [params for _, params in calls] == [(10,), (3,), (100,)]
    assert all("LIMIT %s" in sql for sql, _ in calls)


def test_id_lookups_and_unknown_records(monkeypatch):
    rows = {
        "evt-known": _incident("evt-known", "2026-08-22T02:00:00Z"),
        "CMP-known": _campaign("CMP-known"),
    }
    calls = []

    def fake(sql, params=()):
        calls.append((sql, params))
        return rows.get(params[0])

    monkeypatch.setattr(retrieval, "_fetch_one", fake)
    assert retrieval.get_incident_by_id("evt-known").event_id == "evt-known"
    assert retrieval.get_incident_by_id("evt-missing") is None
    assert retrieval.get_campaign_by_id("CMP-known").campaign_id == "CMP-known"
    assert retrieval.get_campaign_by_id("CMP-missing") is None
    assert all("%s" in sql and params for sql, params in calls)


def test_recent_order_is_delegated_to_indexed_timestamp(monkeypatch):
    rows = [
        _incident("new", "2026-08-22T03:00:00Z"),
        _incident("old", "2026-08-22T01:00:00Z"),
    ]
    captured = {}

    def fake(sql, params=()):
        captured["sql"] = sql
        return rows

    monkeypatch.setattr(retrieval, "_fetch_all", fake)
    result = retrieval.get_recent_incidents(2)
    assert [row.event_id for row in result] == ["new", "old"]
    assert "ORDER BY timestamp DESC NULLS LAST" in captured["sql"]


def test_high_severity_has_explicit_rank_and_timestamp_order(monkeypatch):
    captured = {}

    def fake(sql, params=()):
        captured["sql"] = sql
        return [
            _incident("critical", "2026-08-22T01:00:00Z", "critical"),
            _incident("high", "2026-08-22T03:00:00Z", "high"),
        ]

    monkeypatch.setattr(retrieval, "_fetch_all", fake)
    result = retrieval.get_high_severity_incidents(2)
    assert [row.severity for row in result] == ["critical", "high"]
    assert "CASE LOWER(severity)" in captured["sql"]
    assert "timestamp DESC NULLS LAST" in captured["sql"]


def test_highest_risk_is_deterministic_by_cvss_confidence_and_timestamp(monkeypatch):
    rows = [
        {**_incident("older", "2026-08-22T01:00:00Z", "critical"),
         "payload": '{"cvss":{"base_score":9.8},"detection":{"confidence":0.95}}'},
        {**_incident("newer", "2026-08-22T02:00:00Z", "critical"),
         "payload": '{"cvss":{"base_score":9.8},"detection":{"confidence":0.95}}'},
        {**_incident("lower-cvss", "2026-08-22T03:00:00Z", "critical"),
         "payload": '{"cvss":{"base_score":8.8},"detection":{"confidence":1.0}}'},
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    first = retrieval.get_highest_risk_incident()
    second = retrieval.get_highest_risk_incident()
    assert first is not None and first.event_id == "newer"
    assert second is not None and second.event_id == first.event_id


def test_risk_aggregations_use_transparent_deterministic_order(monkeypatch):
    rows = [
        {**_incident("a-critical", "2026-08-22T01:00:00Z", "critical"),
         "affected_user": "alice", "source_ip": "192.0.2.1", "threat_type": "web_attack",
         "payload": '{"cvss":{"base_score":9.1}}'},
        {**_incident("b-high", "2026-08-22T03:00:00Z", "high"),
         "affected_user": "bob", "source_ip": "192.0.2.2", "threat_type": "port_scan",
         "payload": '{"cvss":{"base_score":9.9}}'},
        {**_incident("a-high", "2026-08-22T02:00:00Z", "high"),
         "affected_user": "alice", "source_ip": "192.0.2.1", "threat_type": "web_attack",
         "payload": '{"cvss":{"base_score":8.0}}'},
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    users = retrieval.get_top_risky_users(2)
    ips = retrieval.get_top_risky_source_ips(2)
    threats = retrieval.get_top_threat_types(2)
    assert users[0].value == "alice" and users[0].critical_count == 1 and users[0].total_incidents == 2
    assert ips[0].value == "192.0.2.1"
    assert threats[0].value == "web_attack"


def test_campaign_relationships_require_two_persisted_shared_members(monkeypatch):
    linked = retrieval.CampaignRecord(
        "CMP-linked", "critical", 80, None, None,
        {"incident_ids": ["EVT-1", "EVT-2", "EVT-3"]}, True,
    )
    unrelated = retrieval.CampaignRecord(
        "CMP-other", "high", 40, None, None,
        {"members": [{"event_id": "EVT-9"}]}, True,
    )
    monkeypatch.setattr(retrieval, "list_campaigns", lambda limit: [linked, unrelated])
    relationships = retrieval.get_campaign_relationships(["EVT-1", "EVT-2", "EVT-8"])
    assert len(relationships) == 1
    assert relationships[0].campaign.campaign_id == "CMP-linked"
    assert relationships[0].matching_incident_ids == ("EVT-1", "EVT-2")
    assert retrieval.get_campaign_relationships(["EVT-1", "EVT-8"]) == []


def test_read_cursor_rejects_sqlite(monkeypatch):
    monkeypatch.setattr(retrieval, "database_backend", lambda: "sqlite")
    with pytest.raises(retrieval.RetrievalConfigurationError):
        with retrieval._read_cursor():
            pass


def test_read_cursor_sets_transaction_read_only(monkeypatch):
    statements = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def execute(self, sql, params=()):
            statements.append(sql)

    class Connection:
        def transaction(self):
            return self

        def cursor(self):
            return Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    @contextmanager
    def fake_connection():
        yield Connection()

    monkeypatch.setattr(retrieval, "database_backend", lambda: "postgresql")
    monkeypatch.setattr(retrieval, "get_db_connection", fake_connection)
    with retrieval._read_cursor():
        pass
    assert statements == ["SET TRANSACTION READ ONLY"]


def test_transient_connection_failure_retries_once_without_retrying_query_errors(monkeypatch):
    attempts = []

    @contextmanager
    def transient_cursor():
        attempts.append("attempt")
        if len(attempts) == 1:
            raise retrieval.OperationalError("temporary connection failure")
        yield object()

    monkeypatch.setattr(retrieval, "_read_cursor", transient_cursor)
    monkeypatch.setattr(retrieval.time, "sleep", lambda _: None)
    assert retrieval._run_read(lambda cursor: "ok") == "ok"
    assert len(attempts) == 2

    @contextmanager
    def query_error_cursor():
        yield object()

    monkeypatch.setattr(retrieval, "_read_cursor", query_error_cursor)
    calls = []
    with pytest.raises(ValueError):
        retrieval._run_read(lambda cursor: calls.append(cursor) or (_ for _ in ()).throw(ValueError("bad SQL")))
    assert len(calls) == 1


def test_retrieval_source_contains_no_mutating_sql():
    source = open(retrieval.__file__, encoding="utf-8").read().upper()
    for keyword in ("INSERT ", "UPDATE ", "DELETE ", "TRUNCATE ", "ALTER ", "DROP ", "CREATE "):
        assert keyword not in source


def test_time_filters_are_parameterized_and_newest_first(monkeypatch):
    calls = []
    monkeypatch.setattr(
        retrieval, "_fetch_all", lambda sql, params=(): calls.append((sql, params)) or []
    )
    retrieval.search_incidents_by_time(start="2026-08-22T00:00:00Z")
    retrieval.search_incidents_by_time(end="2026-08-22T01:00:00+00:00")
    retrieval.search_incidents_by_time(
        start="2026-08-22T00:00:00Z", end="2026-08-22T01:00:00Z", limit=3
    )
    assert "timestamp >= %s" in calls[0][0]
    assert "timestamp <= %s" in calls[1][0]
    assert "timestamp >= %s AND timestamp <= %s" in calls[2][0]
    assert calls[2][1][-1] == 3
    assert all("ORDER BY timestamp DESC NULLS LAST" in sql for sql, _ in calls)


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("not-a-time", None),
        ("2026-08-22T00:00:00", None),
        ("2026-08-22T02:00:00Z", "2026-08-22T01:00:00Z"),
    ],
)
def test_invalid_time_filters_fail_cleanly(start, end):
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.search_incidents_by_time(start=start, end=end)


def test_source_ip_validation_and_parameterization(monkeypatch):
    calls = []
    monkeypatch.setattr(
        retrieval, "_fetch_all", lambda sql, params=(): calls.append((sql, params)) or []
    )
    retrieval.search_incidents_by_source_ip("192.0.2.1", 2)
    retrieval.search_incidents_by_source_ip("2001:db8::1", 2)
    assert calls[0][1] == ("192.0.2.1", 2)
    assert calls[1][1] == ("2001:db8::1", 2)
    assert all("source_ip = %s" in sql for sql, _ in calls)
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.search_incidents_by_source_ip("not-an-ip")


@pytest.mark.parametrize(
    ("function", "value", "column"),
    [
        (retrieval.search_incidents_by_user, "Alice", "affected_user"),
        (retrieval.search_incidents_by_asset, "HOST-1", "affected_host"),
        (retrieval.search_incidents_by_threat_type, "Web_Attack", "threat_type"),
    ],
)
def test_text_filters_use_case_insensitive_equality(monkeypatch, function, value, column):
    captured = {}

    def fake(sql, params=()):
        captured.update(sql=sql, params=params)
        return []

    monkeypatch.setattr(retrieval, "_fetch_all", fake)
    function(value)
    assert f"LOWER({column}) = LOWER(%s)" in captured["sql"]
    assert captured["params"] == (value, 50)


@pytest.mark.parametrize("status", sorted(retrieval.VALID_INCIDENT_STATUSES))
def test_valid_statuses_are_accepted(monkeypatch, status):
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): [])
    assert retrieval.search_incidents_by_status(status.upper()) == []


def test_invalid_status_is_rejected_before_query(monkeypatch):
    monkeypatch.setattr(
        retrieval,
        "_fetch_all",
        lambda *args, **kwargs: pytest.fail("invalid status reached the database"),
    )
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.search_incidents_by_status("resolved")


def test_combined_filters_have_intersection_semantics(monkeypatch):
    captured = {}

    def fake(sql, params=()):
        captured.update(sql=sql, params=params)
        return []

    monkeypatch.setattr(retrieval, "_fetch_all", fake)
    retrieval.search_incidents(
        source_ip="192.0.2.1",
        user="Alice",
        asset="HOST-1",
        status="OPEN",
        threat_type="Web_Attack",
        limit=500,
    )
    assert " AND ".join(
        [
            "source_ip = %s",
            "LOWER(affected_user) = LOWER(%s)",
            "LOWER(affected_host) = LOWER(%s)",
            "LOWER(threat_type) = LOWER(%s)",
            "LOWER(status) = LOWER(%s)",
        ]
    ) in captured["sql"]
    assert captured["params"] == (
        "192.0.2.1",
        "Alice",
        "HOST-1",
        "Web_Attack",
        "open",
        100,
    )


def test_filter_no_match_returns_empty(monkeypatch):
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): [])
    assert retrieval.search_incidents_by_user("missing-user") == []


def test_filtered_count_uses_exact_parameterized_relational_count(monkeypatch):
    captured = {}

    def fake(sql, params=()):
        captured.update(sql=sql, params=params)
        return {"count": 37}

    monkeypatch.setattr(retrieval, "_fetch_one", fake)
    result = retrieval.count_incidents_filtered(
        severity="CRITICAL", status="OPEN", source_ip="198.51.100.10",
        user="Alice", asset="HOST-1", threat_type="web_attack",
    )
    assert result == 37
    assert "COUNT(*)" in captured["sql"] and "LIMIT" not in captured["sql"]
    assert "LOWER(severity) = %s" in captured["sql"]
    assert captured["params"] == ("critical", "open", "198.51.100.10", "Alice", "HOST-1", "web_attack")


def test_filtered_count_rejects_invalid_allowlisted_values(monkeypatch):
    monkeypatch.setattr(retrieval, "_fetch_one", lambda *args: pytest.fail("invalid filter queried"))
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.count_incidents_filtered(status="deleted")
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.count_incidents_filtered(source_ip="not-an-ip")


def test_nested_payload_value_handles_missing_and_unexpected_types():
    payload = {"raw_event": {"destination_ip": "192.0.2.2"}, "cvss": None}
    assert retrieval.nested_payload_value(payload, "raw_event", "destination_ip") == "192.0.2.2"
    assert retrieval.nested_payload_value(payload, "dashboard", "destination_ip") is None
    assert retrieval.nested_payload_value(payload, "cvss", "base_score") is None
    assert retrieval.nested_payload_value(None, "raw_event") is None


def test_payload_scan_is_bounded_and_reports_truncation(monkeypatch):
    rows = [_incident(str(index), f"2026-08-22T00:00:{index:02d}Z") for index in range(4)]
    captured = {}

    def fake(sql, params=()):
        captured.update(sql=sql, params=params)
        return rows

    monkeypatch.setattr(retrieval, "_fetch_all", fake)
    scan = retrieval._scan_payload_incidents(3)
    assert scan.records_scanned == 3
    assert scan.scan_truncated is True
    assert len(scan.incidents) == 3
    assert captured["params"] == (4,)
    assert "LIMIT %s" in captured["sql"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 500), (25, 25), (0, 1), (5000, 1000), ("bad", 500)],
)
def test_payload_scan_limit_bounding(value, expected):
    assert retrieval.bound_payload_scan_limit(value) == expected


def _payload_incident(
    event_id,
    timestamp,
    *,
    destination_ip=None,
    destination_section="raw_event",
    cvss=None,
    malformed=False,
):
    row = _incident(event_id, timestamp)
    if malformed:
        row["payload"] = "not-json"
        return row
    payload = {}
    if destination_ip is not None:
        payload[destination_section] = {"destination_ip": destination_ip}
    if cvss is not None:
        payload["cvss"] = cvss
    import json

    row["payload"] = json.dumps(payload)
    return row


def test_destination_ip_search_supports_fallback_isolation_order_and_limit(monkeypatch):
    rows = [
        _payload_incident("new", "2026-08-22T03:00:00Z", destination_ip="192.0.2.9"),
        _payload_incident(
            "fallback",
            "2026-08-22T02:00:00Z",
            destination_ip="192.0.2.9",
            destination_section="dashboard",
        ),
        _payload_incident("corrupt", "2026-08-22T01:30:00Z", malformed=True),
        _payload_incident("other", "2026-08-22T01:00:00Z", destination_ip="192.0.2.8"),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    result = retrieval.search_incidents_by_destination_ip("192.0.2.9", limit=1)
    assert [item.event_id for item in result] == ["new"]
    assert retrieval.search_incidents_by_destination_ip("192.0.2.7") == []


def test_destination_ip_validation_happens_before_scan(monkeypatch):
    monkeypatch.setattr(
        retrieval,
        "_scan_payload_incidents",
        lambda: pytest.fail("invalid IP reached payload scan"),
    )
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.search_incidents_by_destination_ip("192.0.2.not-valid")


def test_cvss_normalization_accepts_numeric_types_and_ignores_bad_values():
    fixtures = [
        (_payload_incident("float", "2026-08-22T00:00:00Z", cvss={"base_score": 9.8}), 9.8),
        (_payload_incident("int", "2026-08-22T00:00:00Z", cvss={"base_score": 8}), 8.0),
        (_payload_incident("string", "2026-08-22T00:00:00Z", cvss={"base_score": "7.5"}), 7.5),
    ]
    for row, expected in fixtures:
        record = retrieval._cvss_record(retrieval._incident(row))
        assert record.cvss_score == expected
    for bad in (None, "bad", True, -1, 11, float("inf")):
        row = _payload_incident("bad", "2026-08-22T00:00:00Z", cvss={"base_score": bad})
        assert retrieval._cvss_record(retrieval._incident(row)) is None


def test_highest_cvss_numeric_order_tiebreak_and_malformed_isolation(monkeypatch):
    rows = [
        _payload_incident("ten", "2026-08-22T01:00:00Z", cvss={"base_score": "10.0"}),
        _payload_incident("nine-new", "2026-08-22T03:00:00Z", cvss={"base_score": 9.8}),
        _payload_incident("nine-old", "2026-08-22T02:00:00Z", cvss={"base_score": 9.8}),
        _payload_incident("missing", "2026-08-22T04:00:00Z"),
        _payload_incident("corrupt", "2026-08-22T05:00:00Z", malformed=True),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    result = retrieval.get_highest_cvss_incidents(3)
    assert [item.event_id for item in result] == ["ten", "nine-new", "nine-old"]
    assert all(isinstance(item.cvss_score, float) for item in result)


def test_cvss_severity_filter_is_case_insensitive_and_bounded(monkeypatch):
    rows = [
        _payload_incident(
            "critical-new",
            "2026-08-22T03:00:00Z",
            cvss={"base_score": 9.8, "severity": "Critical", "vector_string": "AV:N"},
        ),
        _payload_incident(
            "critical-old",
            "2026-08-22T02:00:00Z",
            cvss={"base_score": 9, "severity": "critical", "vector": {"AV": "N"}},
        ),
        _payload_incident("high", "2026-08-22T01:00:00Z", cvss={"base_score": 8, "severity": "high"}),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    result = retrieval.search_incidents_by_cvss_severity("CRITICAL", limit=1)
    assert [item.event_id for item in result] == ["critical-new"]
    assert result[0].cvss_vector == "AV:N"
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.search_incidents_by_cvss_severity("urgent")


def _mitre_payload_incident(event_id, timestamp, mitre):
    row = _incident(event_id, timestamp)
    import json

    row["payload"] = json.dumps({"mitre_attack": mitre})
    return row


def test_mitre_normalization_populated_missing_and_unexpected_shapes():
    row = _mitre_payload_incident(
        "mapped",
        "2026-08-22T01:00:00Z",
        {
            "tactics": [{"id": "TA0006", "name": "Credential Access"}, "Discovery"],
            "techniques": [
                {"technique_id": "T1110", "technique_name": "Brute Force"},
                "T1046",
            ],
            "primary": {"technique_id": "T1110", "technique_name": "Brute Force"},
            "kill_chain_stage": "Credential Access",
            "kill_chain_order": 6,
        },
    )
    normalized = retrieval._mitre_incident(retrieval._incident(row))
    assert normalized.tactics == ("Credential Access", "Discovery")
    assert normalized.techniques[0] == retrieval.MITRETechnique("T1110", "Brute Force")
    assert normalized.primary_technique.technique_id == "T1110"
    assert normalized.kill_chain_stage == "Credential Access"
    assert normalized.kill_chain_order == 6

    assert retrieval._mitre_incident(retrieval._incident(_incident("missing", "2026-08-22T00:00:00Z"))) is None
    malformed = _mitre_payload_incident(
        "odd",
        "2026-08-22T00:00:00Z",
        {"tactics": 42, "techniques": {"unexpected": True}, "primary": [], "kill_chain_order": True},
    )
    assert retrieval._mitre_incident(retrieval._incident(malformed)) is None


def test_mitre_summary_counts_incidents_once_and_orders_deterministically(monkeypatch):
    rows = [
        _mitre_payload_incident(
            "one",
            "2026-08-22T03:00:00Z",
            {
                "tactics": [
                    {"name": "Credential Access"},
                    {"name": "Credential Access"},
                    {"name": "Discovery"},
                ],
                "techniques": [
                    {"technique_id": "T1110", "technique_name": "Brute Force"},
                    {"technique_id": "t1110", "technique_name": "Duplicate Name"},
                ],
                "primary": {"technique_id": "T1110", "technique_name": "Brute Force"},
                "kill_chain_stage": "Credential Access",
                "kill_chain_order": 6,
            },
        ),
        _mitre_payload_incident(
            "two",
            "2026-08-22T02:00:00Z",
            {
                "tactics": [{"name": "Discovery"}],
                "techniques": [{"technique_id": "T1046", "technique_name": "Network Service Discovery"}],
                "primary": None,
                "kill_chain_stage": "Discovery",
                "kill_chain_order": 7,
            },
        ),
        _payload_incident("corrupt", "2026-08-22T01:00:00Z", malformed=True),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    summary = retrieval.get_mitre_summary(scan_limit=2)
    assert summary.records_scanned == 2
    assert summary.results_returned == 2
    assert summary.scan_truncated is True
    assert [(item.value, item.count) for item in summary.tactics] == [
        ("Discovery", 2),
        ("Credential Access", 1),
    ]
    assert [(item.technique_id, item.count) for item in summary.techniques] == [
        ("T1046", 1),
        ("T1110", 1),
    ]
    assert [(item.value, item.count) for item in summary.kill_chain_stages] == [
        ("Credential Access", 1),
        ("Discovery", 1),
    ]


def test_mitre_technique_search_by_id_name_case_limit_and_isolation(monkeypatch):
    rows = [
        _mitre_payload_incident(
            "new",
            "2026-08-22T03:00:00Z",
            {"techniques": [{"technique_id": "T1110", "technique_name": "Brute Force"}]},
        ),
        _mitre_payload_incident(
            "old",
            "2026-08-22T02:00:00Z",
            {"primary": {"technique_id": "T1110", "technique_name": "Brute Force"}},
        ),
        _payload_incident("corrupt", "2026-08-22T01:00:00Z", malformed=True),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    assert [item.event_id for item in retrieval.search_incidents_by_mitre_technique("t1110", 1)] == ["new"]
    assert [item.event_id for item in retrieval.search_incidents_by_mitre_technique("BRUTE FORCE")] == ["new", "old"]
    assert retrieval.search_incidents_by_mitre_technique("T9999") == []


def test_mitre_tactic_and_kill_chain_searches_are_exact_newest_first(monkeypatch):
    rows = [
        _mitre_payload_incident(
            "new",
            "2026-08-22T03:00:00Z",
            {"tactics": [{"name": "Discovery"}], "kill_chain_stage": "Discovery"},
        ),
        _mitre_payload_incident(
            "old",
            "2026-08-22T02:00:00Z",
            {"tactics": ["Discovery"], "kill_chain_stage": "Discovery"},
        ),
        _mitre_payload_incident(
            "other",
            "2026-08-22T01:00:00Z",
            {"tactics": [{"name": "Execution"}], "kill_chain_stage": "Execution"},
        ),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    assert [item.event_id for item in retrieval.search_incidents_by_mitre_tactic("DISCOVERY", 1)] == ["new"]
    assert retrieval.search_incidents_by_mitre_tactic("Reconnaissance") == []
    assert [item.event_id for item in retrieval.search_incidents_by_kill_chain_stage("discovery")] == ["new", "old"]
    assert retrieval.search_incidents_by_kill_chain_stage("Impact") == []


def _control_payload_incident(event_id, timestamp, control):
    row = _incident(event_id, timestamp)
    import json

    row["payload"] = json.dumps({"cis": control})
    return row


def test_control_normalization_for_cis_owasp_missing_and_partial_values():
    cis = _control_payload_incident(
        "cis",
        "2026-08-22T02:00:00Z",
        {
            "framework": "CIS Controls v8",
            "benchmark_id": "CIS-6.2",
            "title": "Access Control Management",
            "description": "Stored description",
            "rationale": "Stored rationale",
            "remediation": "Stored remediation",
            "audit_procedure": "Stored audit",
        },
    )
    control = retrieval._incident_controls(retrieval._incident(cis))[0]
    assert control.framework == "CIS"
    assert control.control_id == "CIS-6.2"
    assert control.title == "Access Control Management"
    assert control.remediation == "Stored remediation"
    assert control.audit == "Stored audit"

    owasp = _control_payload_incident(
        "owasp",
        "2026-08-22T01:00:00Z",
        {"framework": "OWASP", "benchmark_id": "OWASP-A04", "title": "Insecure Design"},
    )
    normalized = retrieval._incident_controls(retrieval._incident(owasp))[0]
    assert normalized.framework == "OWASP"
    assert normalized.remediation is None

    for section in (None, {}, [], "unexpected", 42):
        assert retrieval._incident_controls(
            retrieval._incident(_control_payload_incident("empty", "2026-08-22T00:00:00Z", section))
        ) == ()


def test_control_normalization_deduplicates_primary_and_additional_matches():
    row = _control_payload_incident(
        "duplicate",
        "2026-08-22T00:00:00Z",
        {
            "framework": "CIS",
            "benchmark_id": "CIS-8.2",
            "title": "Audit Logs",
            "additional_matches": [
                {"framework": "cis controls v8", "benchmark_id": "cis-8.2", "title": "Duplicate"},
                {"framework": "OWASP", "benchmark_id": "OWASP-A09", "title": "Logging Failures"},
                None,
            ],
        },
    )
    controls = retrieval._incident_controls(retrieval._incident(row))
    assert [(item.framework, item.control_id) for item in controls] == [
        ("CIS", "CIS-8.2"),
        ("OWASP", "OWASP-A09"),
    ]


def test_control_summary_counts_incidents_once_and_orders_deterministically(monkeypatch):
    rows = [
        _control_payload_incident(
            "one",
            "2026-08-22T03:00:00Z",
            {
                "framework": "CIS",
                "benchmark_id": "CIS-2",
                "title": "Second",
                "additional_matches": [
                    {"framework": "CIS", "benchmark_id": "cis-2", "title": "Duplicate"},
                    {"framework": "OWASP", "benchmark_id": "OWASP-A01", "title": "Broken Access"},
                ],
            },
        ),
        _control_payload_incident(
            "two",
            "2026-08-22T02:00:00Z",
            {"framework": "CIS Controls v8", "benchmark_id": "CIS-1", "title": "First"},
        ),
        _payload_incident("corrupt", "2026-08-22T01:00:00Z", malformed=True),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    summary = retrieval.get_control_summary(scan_limit=2)
    assert summary.records_scanned == 2
    assert summary.results_returned == 2
    assert summary.scan_truncated is True
    assert [(item.framework, item.incident_count) for item in summary.frameworks] == [
        ("CIS", 2),
        ("OWASP", 1),
    ]
    assert [(item.control_id, item.incident_count) for item in summary.controls] == [
        ("CIS-1", 1),
        ("CIS-2", 1),
        ("OWASP-A01", 1),
    ]


def test_control_searches_are_exact_case_insensitive_bounded_and_resilient(monkeypatch):
    rows = [
        _control_payload_incident(
            "new",
            "2026-08-22T03:00:00Z",
            {"framework": "CIS", "benchmark_id": "CIS-6.2", "title": "Access Control"},
        ),
        _control_payload_incident(
            "old",
            "2026-08-22T02:00:00Z",
            {"framework": "CIS Controls v8", "benchmark_id": "CIS-6.2", "title": "Access Control"},
        ),
        _payload_incident("corrupt", "2026-08-22T01:00:00Z", malformed=True),
    ]
    monkeypatch.setattr(retrieval, "_fetch_all", lambda sql, params=(): rows)
    assert [item.event_id for item in retrieval.search_incidents_by_control_id("cis-6.2", 1)] == ["new"]
    assert [item.event_id for item in retrieval.search_incidents_by_control_title("ACCESS CONTROL")] == ["new", "old"]
    assert [item.event_id for item in retrieval.search_incidents_by_control_framework("cis")] == ["new", "old"]
    assert retrieval.search_incidents_by_control_id("CIS-99") == []
    assert retrieval.search_incidents_by_control_title("Unknown") == []
    with pytest.raises(retrieval.RetrievalInputError):
        retrieval.search_incidents_by_control_framework("NIST")


def test_incident_control_recommendations_return_only_stored_values(monkeypatch):
    known = _control_payload_incident(
        "known",
        "2026-08-22T00:00:00Z",
        {
            "framework": "OWASP",
            "benchmark_id": "OWASP-A04",
            "title": "Insecure Design",
            "rationale": "Stored rationale",
            "remediation": "Stored remediation",
        },
    )
    rows = {"known": known, "without": _control_payload_incident("without", "2026-08-22T00:00:00Z", None)}
    monkeypatch.setattr(retrieval, "_fetch_one", lambda sql, params=(): rows.get(params[0]))
    result = retrieval.get_control_recommendations_for_incident("known")
    assert result.event_id == "known"
    assert result.controls[0].rationale == "Stored rationale"
    assert result.controls[0].remediation == "Stored remediation"
    assert retrieval.get_control_recommendations_for_incident("without").controls == ()
    assert retrieval.get_control_recommendations_for_incident("missing") is None
