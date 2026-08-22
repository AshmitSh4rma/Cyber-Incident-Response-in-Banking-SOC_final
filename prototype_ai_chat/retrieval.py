"""Bounded, read-only retrieval of core SENTRA PostgreSQL records."""

from __future__ import annotations

import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from db_manager import database_backend, get_db_connection

try:
    from psycopg import OperationalError
    from psycopg_pool import PoolTimeout
except ImportError:  # Covered by the existing configuration error at runtime.
    OperationalError = PoolTimeout = ()  # type: ignore[assignment,misc]


DEFAULT_LIMIT = 10
MAX_LIMIT = 100
FILTER_DEFAULT_LIMIT = 50
VALID_INCIDENT_STATUSES = frozenset({"open", "closed", "investigating"})
DEFAULT_PAYLOAD_SCAN_LIMIT = 500
MAX_PAYLOAD_SCAN_LIMIT = 1000
VALID_CVSS_SEVERITIES = frozenset({"none", "low", "medium", "high", "critical"})
VALID_CONTROL_FRAMEWORKS = frozenset({"cis", "owasp"})


class RetrievalConfigurationError(RuntimeError):
    """Raised when retrieval is not configured for PostgreSQL."""


class RetrievalInputError(ValueError):
    """Raised when a retrieval filter is invalid."""


@dataclass(frozen=True)
class ParsedPayload:
    value: dict[str, Any]
    valid: bool


@dataclass(frozen=True)
class IncidentRecord:
    event_id: str
    timestamp: str | None
    severity: str | None
    status: str | None
    threat_type: str | None
    source_ip: str | None
    affected_user: str | None
    affected_host: str | None
    payload: dict[str, Any]
    payload_valid: bool


@dataclass(frozen=True)
class CampaignRecord:
    campaign_id: str
    severity: str | None
    progression_pct: int | None
    first_seen: str | None
    last_seen: str | None
    payload: dict[str, Any]
    payload_valid: bool


@dataclass(frozen=True)
class CVSSRecord:
    event_id: str
    timestamp: str | None
    incident_severity: str | None
    threat_type: str | None
    cvss_score: float
    cvss_severity: str | None
    cvss_vector: str | dict[str, Any] | None


@dataclass(frozen=True)
class PayloadScan:
    incidents: list[IncidentRecord]
    records_scanned: int
    scan_truncated: bool


@dataclass(frozen=True)
class MITRETechnique:
    technique_id: str | None
    name: str | None


@dataclass(frozen=True)
class MITREIncident:
    event_id: str
    timestamp: str | None
    severity: str | None
    threat_type: str | None
    tactics: tuple[str, ...]
    techniques: tuple[MITRETechnique, ...]
    primary_technique: MITRETechnique | None
    kill_chain_stage: str | None
    kill_chain_order: int | None


@dataclass(frozen=True)
class MITRECount:
    value: str
    count: int


@dataclass(frozen=True)
class MITRETechniqueCount:
    technique_id: str | None
    name: str | None
    count: int


@dataclass(frozen=True)
class MITRESummary:
    records_scanned: int
    results_returned: int
    scan_truncated: bool
    tactics: tuple[MITRECount, ...]
    techniques: tuple[MITRETechniqueCount, ...]
    kill_chain_stages: tuple[MITRECount, ...]


@dataclass(frozen=True)
class ControlRecord:
    event_id: str
    timestamp: str | None
    incident_severity: str | None
    threat_type: str | None
    framework: str | None
    control_id: str | None
    title: str | None
    description: str | None
    rationale: str | None
    remediation: str | None
    audit: str | None


@dataclass(frozen=True)
class ControlCount:
    framework: str | None
    control_id: str | None
    title: str | None
    incident_count: int


@dataclass(frozen=True)
class FrameworkCount:
    framework: str
    incident_count: int


@dataclass(frozen=True)
class ControlSummary:
    records_scanned: int
    results_returned: int
    scan_truncated: bool
    frameworks: tuple[FrameworkCount, ...]
    controls: tuple[ControlCount, ...]


@dataclass(frozen=True)
class IncidentControlRecommendations:
    event_id: str
    controls: tuple[ControlRecord, ...]


@dataclass(frozen=True)
class RiskAggregate:
    value: str
    total_incidents: int
    critical_count: int
    high_count: int
    max_cvss: float | None
    latest_activity: str | None


@dataclass(frozen=True)
class CampaignRelationship:
    campaign: CampaignRecord
    matching_incident_ids: tuple[str, ...]


def parse_payload(raw: Any) -> ParsedPayload:
    """Parse a TEXT JSON object without failing the containing retrieval."""
    if isinstance(raw, dict):
        return ParsedPayload(raw, True)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return ParsedPayload({}, False)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ParsedPayload({}, False)
    if not isinstance(value, dict):
        return ParsedPayload({}, False)
    return ParsedPayload(value, True)


def nested_payload_value(payload: Any, *path: str) -> Any | None:
    """Read a nested payload value without assuming intermediate object types."""
    current = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def bound_limit(limit: Any = DEFAULT_LIMIT) -> int:
    """Clamp list limits to 1..100; invalid values use the default of 10."""
    try:
        parsed = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    return max(1, min(parsed, MAX_LIMIT))


def bound_payload_scan_limit(limit: Any = DEFAULT_PAYLOAD_SCAN_LIMIT) -> int:
    """Clamp candidate payload scans independently to 1..1000."""
    try:
        parsed = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_PAYLOAD_SCAN_LIMIT
    return max(1, min(parsed, MAX_PAYLOAD_SCAN_LIMIT))


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RetrievalInputError(f"{field} must be a non-empty string.")
    return value.strip()


def _timestamp(value: Any, field: str) -> tuple[str, datetime] | None:
    """Normalize a timezone-aware timestamp for indexed ISO-8601 TEXT comparison."""
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        candidate = value.strip()
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RetrievalInputError(f"{field} must be a valid ISO-8601 timestamp.") from exc
    else:
        raise RetrievalInputError(f"{field} must be a valid ISO-8601 timestamp.")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RetrievalInputError(f"{field} must include a timezone offset.")
    utc_value = parsed.astimezone(timezone.utc)
    normalized = utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return normalized, utc_value


@contextmanager
def _read_cursor() -> Iterator[Any]:
    if database_backend() != "postgresql":
        raise RetrievalConfigurationError(
            "AI retrieval requires DB_BACKEND=postgresql; SQLite fallback is disabled."
        )
    with get_db_connection() as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION READ ONLY")
                yield cursor


def _connection_errors() -> tuple[type[BaseException], ...]:
    return tuple(error for error in (OperationalError, PoolTimeout) if isinstance(error, type))


def _run_read(operation):
    """Retry one transient connection/acquisition failure; never retry SQL errors."""
    for attempt in range(2):
        try:
            with _read_cursor() as cursor:
                return operation(cursor)
        except _connection_errors():
            if attempt:
                raise
            time.sleep(0.1)
    raise AssertionError("unreachable")


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return _run_read(lambda cursor: (cursor.execute(sql, params), list(cursor.fetchall()))[1])


def _fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    return _run_read(lambda cursor: (cursor.execute(sql, params), cursor.fetchone())[1])


def _incident(row: dict[str, Any]) -> IncidentRecord:
    payload = parse_payload(row.get("payload"))
    return IncidentRecord(
        event_id=row["event_id"],
        timestamp=row.get("timestamp"),
        severity=row.get("severity"),
        status=row.get("status"),
        threat_type=row.get("threat_type"),
        source_ip=row.get("source_ip"),
        affected_user=row.get("affected_user"),
        affected_host=row.get("affected_host"),
        payload=payload.value,
        payload_valid=payload.valid,
    )


def _campaign(row: dict[str, Any]) -> CampaignRecord:
    payload = parse_payload(row.get("payload"))
    return CampaignRecord(
        campaign_id=row["campaign_id"],
        severity=row.get("severity"),
        progression_pct=row.get("progression_pct"),
        first_seen=row.get("first_seen"),
        last_seen=row.get("last_seen"),
        payload=payload.value,
        payload_valid=payload.valid,
    )


_INCIDENT_COLUMNS = """
    event_id, timestamp, severity, status, threat_type, source_ip,
    affected_user, affected_host, payload
"""


def count_incidents() -> int:
    row = _fetch_one("SELECT COUNT(*) AS count FROM incidents")
    return int(row["count"]) if row else 0


def count_incidents_filtered(
    *,
    severity: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
    user: str | None = None,
    asset: str | None = None,
    threat_type: str | None = None,
) -> int:
    """Count incidents using only allowlisted relational filters."""
    clauses: list[str] = []
    params: list[str] = []
    if severity is not None:
        value = _required_text(severity, "severity").casefold()
        if value not in {"critical", "high", "medium", "low"}:
            raise RetrievalInputError("Unsupported incident severity.")
        clauses.append("LOWER(severity) = %s")
        params.append(value)
    if status is not None:
        value = _required_text(status, "status").casefold()
        if value not in VALID_INCIDENT_STATUSES:
            raise RetrievalInputError("Unsupported incident status.")
        clauses.append("LOWER(status) = %s")
        params.append(value)
    if source_ip is not None:
        try:
            value = str(ip_address(_required_text(source_ip, "source_ip")))
        except ValueError as exc:
            raise RetrievalInputError("source_ip must be a valid IPv4 or IPv6 address.") from exc
        clauses.append("source_ip = %s")
        params.append(value)
    for value, field, column in (
        (user, "user", "affected_user"),
        (asset, "asset", "affected_host"),
        (threat_type, "threat_type", "threat_type"),
    ):
        if value is not None:
            normalized = _required_text(value, field)
            clauses.append(f"LOWER({column}) = LOWER(%s)")
            params.append(normalized)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    row = _fetch_one("SELECT COUNT(*) AS count FROM incidents" + where, tuple(params))
    return int(row["count"]) if row else 0


def get_recent_incidents(limit: Any = DEFAULT_LIMIT) -> list[IncidentRecord]:
    rows = _fetch_all(
        f"""
        SELECT {_INCIDENT_COLUMNS}
        FROM incidents
        ORDER BY timestamp DESC NULLS LAST, event_id ASC
        LIMIT %s
        """,
        (bound_limit(limit),),
    )
    return [_incident(row) for row in rows]


def get_high_severity_incidents(limit: Any = DEFAULT_LIMIT) -> list[IncidentRecord]:
    rows = _fetch_all(
        f"""
        SELECT {_INCIDENT_COLUMNS}
        FROM incidents
        WHERE LOWER(severity) IN ('critical', 'high')
        ORDER BY CASE LOWER(severity)
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
        END DESC, timestamp DESC NULLS LAST, event_id ASC
        LIMIT %s
        """,
        (bound_limit(limit),),
    )
    return [_incident(row) for row in rows]


def get_highest_risk_incident() -> IncidentRecord | None:
    """Select one incident by severity, CVSS, confidence, then recency."""
    rows = _fetch_all(
        f"""
        SELECT {_INCIDENT_COLUMNS}
        FROM incidents
        WHERE CASE LOWER(severity)
            WHEN 'critical' THEN 4 WHEN 'high' THEN 3
            WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END = (
                SELECT MAX(CASE LOWER(severity)
                    WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                FROM incidents
            )
        ORDER BY timestamp DESC NULLS LAST, event_id ASC
        LIMIT %s
        """,
        (MAX_PAYLOAD_SCAN_LIMIT,),
    )
    incidents = [_incident(row) for row in rows]
    if not incidents:
        return None

    def numeric(value: Any, default: float = -1.0) -> float:
        if isinstance(value, bool):
            return default
        try:
            result = float(value)
        except (TypeError, ValueError):
            return default
        return result if math.isfinite(result) else default

    def timestamp(value: str | None) -> float:
        if not value:
            return float("-inf")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            return float("-inf")

    def rank(incident: IncidentRecord) -> tuple[float, float, float, str]:
        cvss = _cvss_record(incident)
        confidence = nested_payload_value(incident.payload, "detection", "confidence")
        if confidence is None:
            confidence = nested_payload_value(incident.payload, "dashboard", "confidence")
        # event_id is a deterministic final tie-breaker after the documented
        # severity (pre-filtered), CVSS, confidence, and timestamp ordering.
        return (
            cvss.cvss_score if cvss else -1.0,
            numeric(confidence),
            timestamp(incident.timestamp),
            incident.event_id,
        )

    return max(incidents, key=rank)


def get_incident_by_id(event_id: str) -> IncidentRecord | None:
    row = _fetch_one(
        f"SELECT {_INCIDENT_COLUMNS} FROM incidents WHERE event_id = %s",
        (event_id,),
    )
    return _incident(row) if row else None


def _scan_payload_incidents(scan_limit: Any = DEFAULT_PAYLOAD_SCAN_LIMIT) -> PayloadScan:
    bounded = bound_payload_scan_limit(scan_limit)
    # Fetch one extra row so callers can distinguish a complete scan from truncation.
    rows = _fetch_all(
        f"""
        SELECT {_INCIDENT_COLUMNS}
        FROM incidents
        ORDER BY timestamp DESC NULLS LAST, event_id ASC
        LIMIT %s
        """,
        (bounded + 1,),
    )
    truncated = len(rows) > bounded
    selected = rows[:bounded]
    return PayloadScan(
        incidents=[_incident(row) for row in selected],
        records_scanned=len(selected),
        scan_truncated=truncated,
    )


def _payload_ip(incident: IncidentRecord, key: str) -> str | None:
    for section in ("raw_event", "dashboard"):
        value = nested_payload_value(incident.payload, section, key)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            return str(ip_address(value.strip()))
        except ValueError:
            continue
    return None


def _cvss_record(incident: IncidentRecord) -> CVSSRecord | None:
    raw_score = nested_payload_value(incident.payload, "cvss", "base_score")
    if isinstance(raw_score, bool):
        return None
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not 0 <= score <= 10:
        return None

    raw_severity = nested_payload_value(incident.payload, "cvss", "severity")
    severity = (
        raw_severity.strip().lower()
        if isinstance(raw_severity, str) and raw_severity.strip()
        else None
    )
    vector = nested_payload_value(incident.payload, "cvss", "vector_string")
    if not isinstance(vector, str) or not vector.strip():
        vector = nested_payload_value(incident.payload, "cvss", "vector")
    if not isinstance(vector, (str, dict)):
        vector = None
    return CVSSRecord(
        event_id=incident.event_id,
        timestamp=incident.timestamp,
        incident_severity=incident.severity,
        threat_type=incident.threat_type,
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
    )


def _clean_optional_text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _mitre_technique(value: Any) -> MITRETechnique | None:
    if isinstance(value, str):
        text = _clean_optional_text(value)
        if not text:
            return None
        if text.upper().startswith("T") and text[1:].replace(".", "").isdigit():
            return MITRETechnique(text.upper(), None)
        return MITRETechnique(None, text)
    if not isinstance(value, dict):
        return None
    technique_id = _clean_optional_text(value.get("technique_id") or value.get("id"))
    name = _clean_optional_text(value.get("technique_name") or value.get("name"))
    if technique_id:
        technique_id = technique_id.upper()
    return MITRETechnique(technique_id, name) if technique_id or name else None


def _technique_key(technique: MITRETechnique) -> tuple[str, str]:
    if technique.technique_id:
        return (technique.technique_id.casefold(), "")
    return ("", (technique.name or "").casefold())


def _normalize_tactics(value: Any) -> tuple[str, ...]:
    candidates = value if isinstance(value, list) else [value]
    tactics: dict[str, str] = {}
    for candidate in candidates:
        if isinstance(candidate, dict):
            text = _clean_optional_text(candidate.get("name") or candidate.get("tactic_name"))
        else:
            text = _clean_optional_text(candidate)
        if text:
            tactics.setdefault(text.casefold(), text)
    return tuple(tactics.values())


def _normalize_techniques(value: Any) -> tuple[MITRETechnique, ...]:
    candidates = value if isinstance(value, list) else [value]
    techniques: dict[tuple[str, str], MITRETechnique] = {}
    for candidate in candidates:
        technique = _mitre_technique(candidate)
        if technique:
            techniques.setdefault(_technique_key(technique), technique)
    return tuple(techniques.values())


def _mitre_incident(incident: IncidentRecord) -> MITREIncident | None:
    attack = nested_payload_value(incident.payload, "mitre_attack")
    if not isinstance(attack, dict):
        return None
    tactics = _normalize_tactics(attack.get("tactics"))
    techniques = _normalize_techniques(attack.get("techniques"))
    primary = _mitre_technique(attack.get("primary"))
    stage = _clean_optional_text(attack.get("kill_chain_stage"))
    raw_order = attack.get("kill_chain_order")
    order = raw_order if isinstance(raw_order, int) and not isinstance(raw_order, bool) else None
    if not any((tactics, techniques, primary, stage)):
        return None
    return MITREIncident(
        event_id=incident.event_id,
        timestamp=incident.timestamp,
        severity=incident.severity,
        threat_type=incident.threat_type,
        tactics=tactics,
        techniques=techniques,
        primary_technique=primary,
        kill_chain_stage=stage,
        kill_chain_order=order,
    )


def _incident_techniques(record: MITREIncident) -> tuple[MITRETechnique, ...]:
    combined = list(record.techniques)
    if record.primary_technique:
        combined.append(record.primary_technique)
    unique: dict[tuple[str, str], MITRETechnique] = {}
    for technique in combined:
        unique.setdefault(_technique_key(technique), technique)
    return tuple(unique.values())


def get_mitre_summary(scan_limit: Any = DEFAULT_PAYLOAD_SCAN_LIMIT) -> MITRESummary:
    """Count incidents containing each MITRE value, never duplicate occurrences."""
    scan = _scan_payload_incidents(scan_limit)
    records = [record for incident in scan.incidents if (record := _mitre_incident(incident))]
    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[tuple[str, str]] = Counter()
    technique_values: dict[tuple[str, str], MITRETechnique] = {}
    stage_counts: Counter[str] = Counter()
    stage_values: dict[str, str] = {}
    tactic_values: dict[str, str] = {}
    for record in records:
        for tactic in {item.casefold(): item for item in record.tactics}.values():
            key = tactic.casefold()
            tactic_values.setdefault(key, tactic)
            tactic_counts[key] += 1
        for technique in _incident_techniques(record):
            key = _technique_key(technique)
            technique_values.setdefault(key, technique)
            technique_counts[key] += 1
        if record.kill_chain_stage:
            key = record.kill_chain_stage.casefold()
            stage_values.setdefault(key, record.kill_chain_stage)
            stage_counts[key] += 1

    tactics = tuple(
        MITRECount(tactic_values[key], count)
        for key, count in sorted(tactic_counts.items(), key=lambda item: (-item[1], item[0]))
    )
    techniques = tuple(
        MITRETechniqueCount(
            technique_values[key].technique_id,
            technique_values[key].name,
            count,
        )
        for key, count in sorted(technique_counts.items(), key=lambda item: (-item[1], item[0]))
    )
    stages = tuple(
        MITRECount(stage_values[key], count)
        for key, count in sorted(stage_counts.items(), key=lambda item: (-item[1], item[0]))
    )
    return MITRESummary(
        records_scanned=scan.records_scanned,
        results_returned=len(records),
        scan_truncated=scan.scan_truncated,
        tactics=tactics,
        techniques=techniques,
        kill_chain_stages=stages,
    )


def search_incidents_by_mitre_technique(
    technique: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    target = _required_text(technique, "technique").casefold()
    scan = _scan_payload_incidents()
    matches = []
    for incident in scan.incidents:
        record = _mitre_incident(incident)
        if record and any(
            target in {(item.technique_id or "").casefold(), (item.name or "").casefold()}
            for item in _incident_techniques(record)
        ):
            matches.append(incident)
    return matches[:bound_limit(limit)]


def search_incidents_by_mitre_tactic(
    tactic: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    target = _required_text(tactic, "tactic").casefold()
    scan = _scan_payload_incidents()
    matches = [
        incident
        for incident in scan.incidents
        if (record := _mitre_incident(incident))
        and target in {item.casefold() for item in record.tactics}
    ]
    return matches[:bound_limit(limit)]


def search_incidents_by_kill_chain_stage(
    stage: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    target = _required_text(stage, "stage").casefold()
    scan = _scan_payload_incidents()
    matches = [
        incident
        for incident in scan.incidents
        if (record := _mitre_incident(incident))
        and record.kill_chain_stage
        and record.kill_chain_stage.casefold() == target
    ]
    return matches[:bound_limit(limit)]


def _control_framework(value: Any) -> str | None:
    text = _clean_optional_text(value)
    if not text:
        return None
    normalized = text.casefold()
    if normalized == "cis" or normalized.startswith("cis controls"):
        return "CIS"
    if normalized == "owasp" or normalized.startswith("owasp "):
        return "OWASP"
    return None


def _control_record(incident: IncidentRecord, value: Any) -> ControlRecord | None:
    if not isinstance(value, dict):
        return None
    framework = _control_framework(value.get("framework"))
    control_id = _clean_optional_text(
        value.get("benchmark_id") or value.get("control_id")
    )
    title = _clean_optional_text(value.get("title"))
    description = _clean_optional_text(value.get("description"))
    rationale = _clean_optional_text(value.get("rationale"))
    remediation = _clean_optional_text(value.get("remediation"))
    audit = _clean_optional_text(value.get("audit_procedure") or value.get("audit"))
    if not any((framework, control_id, title, description, rationale, remediation, audit)):
        return None
    return ControlRecord(
        event_id=incident.event_id,
        timestamp=incident.timestamp,
        incident_severity=incident.severity,
        threat_type=incident.threat_type,
        framework=framework,
        control_id=control_id,
        title=title,
        description=description,
        rationale=rationale,
        remediation=remediation,
        audit=audit,
    )


def _incident_controls(incident: IncidentRecord) -> tuple[ControlRecord, ...]:
    section = nested_payload_value(incident.payload, "cis")
    candidates: list[Any]
    if isinstance(section, list):
        candidates = list(section)
    elif isinstance(section, dict):
        candidates = [section]
        additional = section.get("additional_matches")
        if isinstance(additional, list):
            candidates.extend(additional)
    else:
        return ()
    unique: dict[tuple[str, str, str], ControlRecord] = {}
    for candidate in candidates:
        control = _control_record(incident, candidate)
        if not control:
            continue
        key = (
            (control.framework or "").casefold(),
            (control.control_id or "").casefold(),
            "" if control.control_id else (control.title or "").casefold(),
        )
        unique.setdefault(key, control)
    return tuple(unique.values())


def get_control_summary(scan_limit: Any = DEFAULT_PAYLOAD_SCAN_LIMIT) -> ControlSummary:
    """Count incident presence per framework and control without duplicate inflation."""
    scan = _scan_payload_incidents(scan_limit)
    framework_counts: Counter[str] = Counter()
    control_counts: Counter[tuple[str, str, str]] = Counter()
    control_values: dict[tuple[str, str, str], ControlRecord] = {}
    incidents_with_controls = 0
    for incident in scan.incidents:
        controls = _incident_controls(incident)
        if not controls:
            continue
        incidents_with_controls += 1
        for framework in {item.framework for item in controls if item.framework}:
            framework_counts[framework] += 1
        for control in controls:
            key = (
                (control.framework or "").casefold(),
                (control.control_id or "").casefold(),
                "" if control.control_id else (control.title or "").casefold(),
            )
            control_values.setdefault(key, control)
            control_counts[key] += 1
    frameworks = tuple(
        FrameworkCount(framework, count)
        for framework, count in sorted(
            framework_counts.items(), key=lambda item: (-item[1], item[0].casefold())
        )
    )
    controls = tuple(
        ControlCount(
            control_values[key].framework,
            control_values[key].control_id,
            control_values[key].title,
            count,
        )
        for key, count in sorted(control_counts.items(), key=lambda item: (-item[1], item[0]))
    )
    return ControlSummary(
        records_scanned=scan.records_scanned,
        results_returned=incidents_with_controls,
        scan_truncated=scan.scan_truncated,
        frameworks=frameworks,
        controls=controls,
    )


def search_incidents_by_control_id(
    control_id: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    target = _required_text(control_id, "control_id").casefold()
    scan = _scan_payload_incidents()
    matches = [
        incident
        for incident in scan.incidents
        if any((item.control_id or "").casefold() == target for item in _incident_controls(incident))
    ]
    return matches[:bound_limit(limit)]


def search_incidents_by_control_title(
    title: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    target = _required_text(title, "title").casefold()
    scan = _scan_payload_incidents()
    matches = [
        incident
        for incident in scan.incidents
        if any((item.title or "").casefold() == target for item in _incident_controls(incident))
    ]
    return matches[:bound_limit(limit)]


def search_incidents_by_control_framework(
    framework: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    raw = _required_text(framework, "framework")
    normalized = _control_framework(raw)
    if not normalized or normalized.casefold() not in VALID_CONTROL_FRAMEWORKS:
        allowed = ", ".join(sorted(name.upper() for name in VALID_CONTROL_FRAMEWORKS))
        raise RetrievalInputError(f"framework must be one of: {allowed}.")
    scan = _scan_payload_incidents()
    matches = [
        incident
        for incident in scan.incidents
        if any(item.framework == normalized for item in _incident_controls(incident))
    ]
    return matches[:bound_limit(limit)]


def get_control_recommendations_for_incident(
    event_id: str,
) -> IncidentControlRecommendations | None:
    incident = get_incident_by_id(_required_text(event_id, "event_id"))
    if incident is None:
        return None
    return IncidentControlRecommendations(
        event_id=incident.event_id,
        controls=_incident_controls(incident),
    )


def search_incidents_by_destination_ip(
    destination_ip: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    candidate = _required_text(destination_ip, "destination_ip")
    try:
        normalized = str(ip_address(candidate))
    except ValueError as exc:
        raise RetrievalInputError(
            "destination_ip must be a valid IPv4 or IPv6 address."
        ) from exc
    result_limit = bound_limit(limit)
    scan = _scan_payload_incidents()
    return [
        incident
        for incident in scan.incidents
        if _payload_ip(incident, "destination_ip") == normalized
    ][:result_limit]


def get_highest_cvss_incidents(limit: Any = DEFAULT_LIMIT) -> list[CVSSRecord]:
    scan = _scan_payload_incidents()
    records = [record for incident in scan.incidents if (record := _cvss_record(incident))]
    records.sort(key=lambda item: (item.cvss_score, item.timestamp or ""), reverse=True)
    return records[:bound_limit(limit)]


def search_incidents_by_cvss_severity(
    severity: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[CVSSRecord]:
    normalized = _required_text(severity, "severity").lower()
    if normalized not in VALID_CVSS_SEVERITIES:
        allowed = ", ".join(sorted(VALID_CVSS_SEVERITIES))
        raise RetrievalInputError(f"CVSS severity must be one of: {allowed}.")
    scan = _scan_payload_incidents()
    records = [
        record
        for incident in scan.incidents
        if (record := _cvss_record(incident)) and record.cvss_severity == normalized
    ]
    return records[:bound_limit(limit)]


def search_incidents(
    *,
    start: str | datetime | None = None,
    end: str | datetime | None = None,
    source_ip: str | None = None,
    user: str | None = None,
    asset: str | None = None,
    status: str | None = None,
    threat_type: str | None = None,
    limit: Any = FILTER_DEFAULT_LIMIT,
) -> list[IncidentRecord]:
    """Apply allowlisted relational filters; incident timestamps are ISO-8601 TEXT."""
    start_value = _timestamp(start, "start")
    end_value = _timestamp(end, "end")
    if start_value and end_value and start_value[1] > end_value[1]:
        raise RetrievalInputError("start must not be later than end.")

    clauses: list[str] = []
    params: list[Any] = []
    if start_value:
        clauses.append("timestamp >= %s")
        params.append(start_value[0])
    if end_value:
        clauses.append("timestamp <= %s")
        params.append(end_value[0])
    if source_ip is not None:
        candidate = _required_text(source_ip, "source_ip")
        try:
            normalized_ip = str(ip_address(candidate))
        except ValueError as exc:
            raise RetrievalInputError("source_ip must be a valid IPv4 or IPv6 address.") from exc
        clauses.append("source_ip = %s")
        params.append(normalized_ip)
    for value, field, column in (
        (user, "user", "affected_user"),
        (asset, "asset", "affected_host"),
        (threat_type, "threat_type", "threat_type"),
    ):
        if value is not None:
            clauses.append(f"LOWER({column}) = LOWER(%s)")
            params.append(_required_text(value, field))
    if status is not None:
        normalized_status = _required_text(status, "status").lower()
        if normalized_status not in VALID_INCIDENT_STATUSES:
            allowed = ", ".join(sorted(VALID_INCIDENT_STATUSES))
            raise RetrievalInputError(f"status must be one of: {allowed}.")
        clauses.append("LOWER(status) = LOWER(%s)")
        params.append(normalized_status)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = _fetch_all(
        f"""
        SELECT {_INCIDENT_COLUMNS}
        FROM incidents
        {where}
        ORDER BY timestamp DESC NULLS LAST, event_id ASC
        LIMIT %s
        """,
        (*params, bound_limit(limit)),
    )
    return [_incident(row) for row in rows]


def search_incidents_by_time(
    start: str | datetime | None = None,
    end: str | datetime | None = None,
    limit: Any = FILTER_DEFAULT_LIMIT,
) -> list[IncidentRecord]:
    return search_incidents(start=start, end=end, limit=limit)


def search_incidents_by_source_ip(
    source_ip: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    return search_incidents(source_ip=source_ip, limit=limit)


def search_incidents_by_user(
    user: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    return search_incidents(user=user, limit=limit)


def search_incidents_by_asset(
    asset: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    return search_incidents(asset=asset, limit=limit)


def search_incidents_by_status(
    status: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    return search_incidents(status=status, limit=limit)


def search_incidents_by_threat_type(
    threat_type: str, limit: Any = FILTER_DEFAULT_LIMIT
) -> list[IncidentRecord]:
    return search_incidents(threat_type=threat_type, limit=limit)


def _risk_aggregates(field: str, limit: Any, *, threat_order: bool = False) -> list[RiskAggregate]:
    """Rank one relational dimension using bounded incident evidence."""
    if field not in {"affected_user", "source_ip", "threat_type"}:
        raise RetrievalInputError("Unsupported risk aggregation field.")
    rows = _fetch_all(
        f"""
        SELECT {_INCIDENT_COLUMNS}
        FROM incidents
        WHERE {field} IS NOT NULL AND BTRIM({field}) <> ''
        ORDER BY timestamp DESC NULLS LAST, event_id ASC
        LIMIT %s
        """,
        (MAX_PAYLOAD_SCAN_LIMIT,),
    )
    values: dict[str, dict[str, Any]] = {}
    for incident in (_incident(row) for row in rows):
        value = getattr(incident, field)
        if not isinstance(value, str) or not value.strip():
            continue
        key = value.casefold()
        item = values.setdefault(key, {
            "value": value.strip(), "total": 0, "critical": 0, "high": 0,
            "max_cvss": None, "latest": None,
        })
        item["total"] += 1
        severity = (incident.severity or "").casefold()
        item["critical"] += severity == "critical"
        item["high"] += severity == "high"
        cvss = _cvss_record(incident)
        if cvss and (item["max_cvss"] is None or cvss.cvss_score > item["max_cvss"]):
            item["max_cvss"] = cvss.cvss_score
        if incident.timestamp and (item["latest"] is None or incident.timestamp > item["latest"]):
            item["latest"] = incident.timestamp

    def ranking(item: dict[str, Any]) -> tuple[Any, ...]:
        cvss = item["max_cvss"] if item["max_cvss"] is not None else -1.0
        if threat_order:
            return (-item["critical"], -item["high"], -item["total"], -cvss, item["value"].casefold())
        return (-item["critical"], -item["high"], -cvss, -item["total"],
                _reverse_timestamp_key(item["latest"]), item["value"].casefold())

    ranked = sorted(values.values(), key=ranking)[:bound_limit(limit)]
    return [RiskAggregate(
        item["value"], item["total"], item["critical"], item["high"],
        item["max_cvss"], item["latest"],
    ) for item in ranked]


def _reverse_timestamp_key(value: str | None) -> float:
    if not value:
        return float("inf")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return -parsed.timestamp()
    except ValueError:
        return float("inf")


def get_top_risky_users(limit: Any = DEFAULT_LIMIT) -> list[RiskAggregate]:
    return _risk_aggregates("affected_user", limit)


def get_top_risky_source_ips(limit: Any = DEFAULT_LIMIT) -> list[RiskAggregate]:
    return _risk_aggregates("source_ip", limit)


def get_top_threat_types(limit: Any = DEFAULT_LIMIT) -> list[RiskAggregate]:
    return _risk_aggregates("threat_type", min(bound_limit(limit), 20), threat_order=True)


def list_campaigns(limit: Any = DEFAULT_LIMIT) -> list[CampaignRecord]:
    rows = _fetch_all(
        """
        SELECT campaign_id, severity, progression_pct, first_seen, last_seen, payload
        FROM campaigns
        ORDER BY progression_pct DESC NULLS LAST, last_seen DESC NULLS LAST,
                 campaign_id ASC
        LIMIT %s
        """,
        (bound_limit(limit),),
    )
    return [_campaign(row) for row in rows]


def get_campaign_by_id(campaign_id: str) -> CampaignRecord | None:
    row = _fetch_one(
        """
        SELECT campaign_id, severity, progression_pct, first_seen, last_seen, payload
        FROM campaigns
        WHERE campaign_id = %s
        """,
        (campaign_id,),
    )
    return _campaign(row) if row else None


def _campaign_member_ids(campaign: CampaignRecord) -> tuple[str, ...]:
    raw = (campaign.payload.get("incident_ids") or campaign.payload.get("member_incident_ids")
           or campaign.payload.get("members") or [])
    if not isinstance(raw, list):
        return ()
    members: list[str] = []
    for item in raw:
        if isinstance(item, str):
            members.append(item)
        elif isinstance(item, dict):
            identifier = item.get("event_id") or item.get("incident_id")
            if identifier:
                members.append(str(identifier))
    return tuple(dict.fromkeys(members))


def get_campaign_relationships(
    incident_ids: list[str] | tuple[str, ...], minimum_matches: int = 2
) -> list[CampaignRelationship]:
    """Return persisted campaigns containing at least two requested incidents."""
    requested = {value for value in incident_ids if isinstance(value, str) and value}
    minimum = 1 if minimum_matches <= 1 else 2
    if len(requested) < minimum:
        return []
    relationships = []
    for campaign in list_campaigns(MAX_LIMIT):
        matching = tuple(sorted(requested.intersection(_campaign_member_ids(campaign))))
        if len(matching) >= minimum:
            relationships.append(CampaignRelationship(campaign, matching))
    return relationships
