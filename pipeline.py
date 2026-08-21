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

import time
from typing import Any

from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering
from layer_2_detection.campaign_correlator import correlate_campaigns
from layer_2_detection.detection_orchestrator import run_detection_batch
from layer_3_cis.orchestrator import run_layer3
from layer_4_ai_analysis.incident_report_builder import run_layer4
from layer_5_cvss.cvss_orchestrator import run_cvss
from layer_6_response.response_orchestrator import run_response
from frontend_formatter import format_pipeline_for_frontend


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

    frontend_output = format_pipeline_for_frontend(
        parsed_logs=None,
        layer1_output=layer1,
        layer2_output=layer2,
        layer3_output=layer3,
    )
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

    for event in enriched:
        event["response"] = run_response(event)
    t = mark("layer6_response", t)

    # Stamp each event with the campaign it belongs to. The correlator works on
    # detection-stage events, so match on the ids it returned.
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
            }
        else:
            event["campaign"] = None

    frontend_output["events"] = enriched
    frontend_output["campaigns"] = campaign_result["campaigns"]
    frontend_output["campaign_summary"] = campaign_result["summary"]

    timing["total"] = round(time.perf_counter() - started, 3)
    frontend_output["timing"] = timing

    return frontend_output
