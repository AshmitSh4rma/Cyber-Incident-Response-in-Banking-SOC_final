"""
The SOC pipeline, in one place.

api_server.py and dev_run.py both used to carry their own copy of the layer
sequence, which drifted — the API wrote one output file where the CLI wrote two,
and only one of them knew about later layers. Both now call run_full_pipeline so
there is exactly one definition of what "running the pipeline" means.

Order matters and is not arbitrary:

    L1 features -> L2 detection -> L3 CIS -> format -> L2.5 campaigns
       -> L4 analysis -> L5 CVSS -> L6 response

Campaign correlation is numbered 2.5 because it reasons over Layer 2's verdicts,
but it executes after formatting: it needs the stable event_id the formatter
assigns, otherwise the campaign's member ids would not match any incident the
dashboard can open.
"""

import contextlib
import time
from datetime import UTC, datetime
from typing import Any

from frontend_formatter import format_pipeline_for_frontend
from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering
from layer_2_detection.campaign_correlator import correlate_campaigns
from layer_2_detection.detection_orchestrator import run_detection_batch
from layer_3_cis.orchestrator import run_layer3
from layer_4_ai_analysis.incident_report_builder import run_layer4
from layer_5_cvss.cvss_orchestrator import run_cvss
from layer_6_response.response_orchestrator import run_response
from regulatory_clock import for_campaign, for_incident

# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 accumulates per-source history in module-level stores — unique ports
# seen per IP, failed logins per user, byte ratios, reporting intervals. That is
# correct for a live sensor and wrong for a repeatable run: replay two scenarios
# in one process and the second one's verdicts depend on the first one's traffic.
#
# It matters most for the settings screen, which answers "what would this change
# do" by running the pipeline twice. If the second run inherits the first run's
# history, the comparison measures the wrong thing and the answer is confidently
# wrong. So a caller that needs a clean slate can ask for one.
# ─────────────────────────────────────────────────────────────────────────────

_STATEFUL_STORES = [
    ("layer_1_feature_engineering.engine_1_temporal.tsfresh_extractor", "_event_store"),
    ("layer_1_feature_engineering.engine_2_behavioral.user_profiler", "_user_store"),
    ("layer_1_feature_engineering.engine_2_behavioral.baseline_comparator", "_baseline_store"),
    ("layer_1_feature_engineering.engine_3_statistical.pattern_detector", "_pattern_store"),
    ("layer_1_feature_engineering.engine_3_statistical.frequency_analyzer", "_rate_store"),
    ("layer_1_feature_engineering.engine_3_statistical.frequency_analyzer", "_rate_history"),
    ("layer_1_feature_engineering.engine_4_network.protocol_profiler", "_protocol_store"),
    ("layer_1_feature_engineering.engine_5_web.http_analyzer", "_http_store"),
    ("layer_1_feature_engineering.engine_5_web.session_profiler", "_session_store"),
    ("layer_1_feature_engineering.engine_6_iot.device_profiler", "_device_store"),
    ("layer_1_feature_engineering.engine_6_iot.telemetry_analyzer", "_telemetry_store"),
]


@contextlib.contextmanager
def isolated_state():
    """
    Run with a clean Layer 1, then put the process back as it was.

    `reset_state()` on its own is destructive: the settings screen's "preview the
    effect" button would clear the running system's accumulated baselines and rate
    history, so the very next real upload was scored against nothing. The button
    is presented as consequence-free, and it has to be.

    A shallow copy per store is enough — the engines mutate the containers, not
    the values inside them.
    """
    import importlib

    saved: list[tuple[Any, Any]] = []
    for module_name, attr in _STATEFUL_STORES:
        try:
            store = getattr(importlib.import_module(module_name), attr)
        except (ImportError, AttributeError):
            continue
        saved.append((store, store.copy() if hasattr(store, "copy") else None))

    reset_state()
    try:
        yield
    finally:
        for store, snapshot in saved:
            if snapshot is None:
                continue
            store.clear()
            # deque has extend; dict has update. Both restore in place, which is
            # what matters — the engines closed over these objects at import.
            if hasattr(store, "update"):
                store.update(snapshot)
            else:
                store.extend(snapshot)


def reset_state() -> int:
    """
    Forget everything Layer 1 has learned, so the next run starts cold.

    Cleared in place rather than rebound: several engines close over the store
    object at import, so replacing the attribute would leave them writing to the
    old one. Returns how many stores were cleared, which is how a test notices
    when an engine grows a new one that nobody added here.
    """
    import importlib

    cleared = 0
    for module_name, attr in _STATEFUL_STORES:
        try:
            store = getattr(importlib.import_module(module_name), attr)
        except (ImportError, AttributeError):
            continue
        if hasattr(store, "clear"):
            store.clear()
            cleared += 1
    return cleared


def run_full_pipeline(normalized_records: list[dict]) -> dict[str, Any]:
    """
    Run every layer over already-normalised records.

    Returns the frontend contract plus the campaign set and timing:
        {
          "status": "success",
          "total_events": int,
          "events": [ ...enriched events... ],
          "campaigns": [ ... ],
          "campaign_summary": { ... },
          "timing": { per-layer seconds }
        }
    """
    timing: dict[str, float] = {}
    started = time.perf_counter()

    def mark(stage: str, t0: float) -> float:
        now = time.perf_counter()
        timing[stage] = round(now - t0, 3)
        return now

    t = time.perf_counter()
    layer1 = [run_feature_engineering(rec) for rec in normalized_records]
    t = mark("layer1_features", t)

    layer2 = run_detection_batch(layer1)
    t = mark("layer2_detection", t)

    layer3 = run_layer3(layer2)
    t = mark("layer3_cis", t)

    frontend_output = format_pipeline_for_frontend(layer3)
    t = mark("format", t)

    # Layer 2.5 — runs after formatting because correlation needs the stable
    # event_id the formatter assigns, and the normalised dashboard fields it
    # populates. It reads only detection + ATT&CK, both already present.
    campaign_result = correlate_campaigns(frontend_output["events"])
    t = mark("layer2_5_campaigns", t)

    enriched = run_layer4(frontend_output["events"])
    t = mark("layer4_analysis", t)

    for event in enriched:
        event["cvss"] = run_cvss(event["ai_analysis"])
    t = mark("layer5_cvss", t)

    # Stamp each event with the campaign it belongs to. The correlator works on
    # detection-stage events, so match on the ids it returned.
    #
    # Deliberately before Layer 6 rather than after: response planning gates on
    # blast radius, and how many hosts an action would really touch is a property
    # of the campaign, not of the single alert in front of it. Isolating one host
    # that happens to be one of five the same intruder owns is not a one-host
    # decision.
    campaign_by_incident: dict[str, dict[str, Any]] = {}
    for campaign in campaign_result["campaigns"]:
        for incident_id in campaign["incident_ids"]:
            campaign_by_incident[incident_id] = campaign

    for event in enriched:
        campaign = campaign_by_incident.get(event.get("event_id"))
        if campaign:
            event["campaign"] = {
                "campaign_id": campaign["campaign_id"],
                "name": campaign["name"],
                "severity": campaign["severity"],
                "incident_count": campaign["incident_count"],
                "furthest_stage": campaign["furthest_stage"],
                "progression_pct": campaign["progression_pct"],
                "asset_count": len(campaign.get("assets") or []),
            }
        else:
            event["campaign"] = None

    for event in enriched:
        event["response"] = run_response(event)
    t = mark("layer6_response", t)

    # Regulatory notification clocks.
    #
    # The clock origin is NOW, not the log timestamp: these deadlines run from the
    # moment of determination, and determination is what just happened here. Using
    # the log timestamp would show every historical demo record as overdue.
    determined_at = datetime.now(UTC).isoformat()

    for campaign in campaign_result["campaigns"]:
        campaign["determined_at"] = determined_at
        campaign["notification"] = for_campaign(campaign)

    for event in enriched:
        if event.get("campaign"):
            # A campaign is one incident to a regulator, so the clock lives on the
            # campaign and the member incidents point at it rather than each
            # starting a duplicate deadline.
            event["notification"] = None
        else:
            event["determined_at"] = determined_at
            event["notification"] = for_incident({**event, "determined_at": determined_at})

    frontend_output["events"] = enriched
    frontend_output["campaigns"] = campaign_result["campaigns"]
    frontend_output["campaign_summary"] = campaign_result["summary"]

    timing["total"] = round(time.perf_counter() - started, 3)
    frontend_output["timing"] = timing

    return frontend_output
