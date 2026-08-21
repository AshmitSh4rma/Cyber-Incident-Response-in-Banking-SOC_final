"""
Layer 2 -> Layer 3 integration test.

Runs the real sample logs through Layers 1 and 2, then asserts Layer 3 maps the
results onto CIS benchmark content. Previously this read a hardcoded
`output_detection.json` from the working directory, which does not exist in a
fresh clone, so pytest failed at import time.
"""

import json
from pathlib import Path

import pytest

from layer_1_feature_engineering.ingestion_orchestrator import process_json_text
from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering
from layer_2_detection.detection_orchestrator import run_detection_batch
from layer_3_cis.orchestrator import run_layer3

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOGS = ROOT / "layer_1_feature_engineering" / "sample_logs.json"


@pytest.fixture(scope="module")
def layer3_output():
    if not SAMPLE_LOGS.exists():
        pytest.skip(f"sample logs not found at {SAMPLE_LOGS}")

    records = process_json_text(SAMPLE_LOGS.read_text(encoding="utf-8"))
    layer1 = [run_feature_engineering(rec) for rec in records]
    layer2 = run_detection_batch(layer1)
    return run_layer3(layer2)


def test_layer3_returns_one_entry_per_event(layer3_output):
    assert isinstance(layer3_output, list)
    assert len(layer3_output) == 6


def test_every_event_carries_a_cis_block(layer3_output):
    for entry in layer3_output:
        assert "cis_benchmark" in entry, f"missing cis_benchmark on {entry.get('source_ip')}"
        assert entry["cis_benchmark"].get("framework")


def test_catalog_retrieval_produces_real_benchmarks(layer3_output):
    """At least some events should match the shipped CIS catalogs, with content."""
    matched = [
        e for e in layer3_output
        if (e.get("cis_benchmark") or {}).get("matched_benchmarks")
    ]
    assert matched, "no event matched any CIS benchmark"

    best = matched[0]["cis_benchmark"]["matched_benchmarks"][0]
    for field in ("benchmark_id", "title", "description"):
        assert best.get(field), f"matched benchmark missing {field}"


def test_web_events_route_to_the_web_engine(layer3_output):
    web = [e for e in layer3_output if str(e.get("log_type", "")).lower() == "web"]
    assert web, "sample data should contain web events"
    for entry in web:
        assert entry["cis_benchmark"]["framework"] == "web_owasp_catalog"


def test_output_is_json_serialisable(layer3_output):
    json.dumps(layer3_output)
