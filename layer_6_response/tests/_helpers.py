"""
Shared builders for the Layer 6 response tests.

The Incident model carries severity inside a nested CVSSData block rather than as
a top-level field; these helpers keep the tests in step with that shape.
"""

from response_layer.models import CVSSData, CVSSVector, Incident, Severity

_SEVERITY_SCORES = {
    Severity.CRITICAL: 9.8,
    Severity.HIGH: 8.1,
    Severity.MEDIUM: 5.3,
    Severity.LOW: 3.1,
    Severity.NONE: 0.0,
}


def make_cvss(severity: Severity = Severity.HIGH) -> CVSSData:
    return CVSSData(
        vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", C="H", I="H", A="N", S="U"),
        vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        base_score=_SEVERITY_SCORES[severity],
        severity=severity,
    )


def make_incident(severity: Severity = Severity.HIGH, **overrides) -> Incident:
    fields = {
        "id": "INC-1",
        "summary": "Test",
        "cvss": make_cvss(severity),
        "confidence": 0.9,
        "source_ip": "1.1.1.1",
        "affected_user": "user1",
        "asset_id": "asset1",
        "mitre_tactics": [],
        "anomaly_score": 0.9,
        "asset_criticality": "High",
    }
    fields.update(overrides)
    return Incident(**fields)
