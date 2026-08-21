"""
Layer 4 fallback test.

Ollama is not available in this environment (and is not part of the demo), so the
important property is that the rule-based fallback still returns a complete,
useful analysis for every incident. Previously this file was an ad-hoc script
with no test functions.
"""

import json
from pathlib import Path

import pytest

from layer_4_ai_analysis.incident_report_builder import run_layer4

ROOT = Path(__file__).resolve().parent.parent
PIPELINE_OUTPUT = ROOT / "frontend_output.json"

REQUIRED_FIELDS = (
    "intent",
    "summary",
    "narrative",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "impact",
)


@pytest.fixture(scope="module")
def enriched_events():
    if not PIPELINE_OUTPUT.exists():
        pytest.skip("run dev_run.py first to generate frontend_output.json")

    data = json.loads(PIPELINE_OUTPUT.read_text(encoding="utf-8"))
    events = data.get("events") if isinstance(data, dict) else data
    if not events:
        pytest.skip("no events in frontend_output.json")

    # Strip any existing analysis so we exercise Layer 4 from scratch.
    stripped = []
    for event in events:
        copy = dict(event)
        copy.pop("ai_analysis", None)
        stripped.append(copy)

    return run_layer4(stripped)


def test_every_event_gets_an_analysis(enriched_events):
    assert enriched_events
    for event in enriched_events:
        assert event.get("ai_analysis"), f"no ai_analysis for {event.get('event_id')}"


def test_analysis_has_all_required_fields(enriched_events):
    for event in enriched_events:
        analysis = event["ai_analysis"]
        for field in REQUIRED_FIELDS:
            assert field in analysis, f"{field} missing for {event.get('event_id')}"
            assert analysis[field] not in (None, "", {}), f"{field} empty for {event.get('event_id')}"


def test_impact_uses_valid_cvss_levels(enriched_events):
    allowed = {"none", "low", "high"}
    for event in enriched_events:
        impact = event["ai_analysis"]["impact"]
        for dimension in ("confidentiality", "integrity", "availability"):
            assert impact.get(dimension) in allowed, (
                f"{dimension}={impact.get(dimension)!r} is not a valid CVSS impact level"
            )


def test_narratives_are_substantive_and_specific(enriched_events):
    """A fallback that emits 'N/A' is worse than useless on an analyst's screen."""
    narratives = []
    for event in enriched_events:
        narrative = event["ai_analysis"]["narrative"]
        assert len(narrative) > 80, f"narrative too thin: {narrative!r}"
        assert "N/A" not in narrative
        narratives.append(narrative)

    # Different incidents must not all share one boilerplate narrative.
    assert len(set(narratives)) > 1, "every incident produced an identical narrative"


def test_metrics_map_onto_the_cvss_engine(enriched_events):
    """Layer 4's output must be directly consumable by Layer 5."""
    from layer_5_cvss.cvss_orchestrator import run_cvss

    for event in enriched_events:
        result = run_cvss(event["ai_analysis"])
        assert isinstance(result.get("base_score"), (int, float))
        assert 0.0 <= result["base_score"] <= 10.0
        assert result.get("vector_string", "").startswith("AV:")
