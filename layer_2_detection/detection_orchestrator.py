from layer_2_detection.engine_1_anomaly.anomaly_orchestrator import run_anomaly
from layer_2_detection.engine_2_threat_analysis.threat_analysis_orchestrator import run_threat_analysis
from layer_2_detection.engine_3_ioc_enrichment.ioc_orchestrator import run_ioc_enrichment
from layer_2_detection.engine_4_correlation.correlation_orchestrator import run_correlation
from layer_2_detection.detection_fusion import fuse_detection
from layer_2_detection.layer1_adapter import adapt_layer1_event
from layer_2_detection.mitre_mapper import enrich_event as enrich_mitre
from layer_2_detection.suppression_checker import (
    load_suppression_rules,
    is_suppressed,
    build_suppressed_detection,
)


def run_detection(event: dict, suppression_rules: list[dict] | None = None) -> dict:
    event = adapt_layer1_event(event)

    # ── Suppression Check ──────────────────────────────────────────────────────
    # Before running any engine, check if this event matches a known FP rule.
    # If it does, short-circuit with a 'suppressed' detection result so the
    # analyst isn't burdened with alerts they've already reviewed and dismissed.
    suppressed, suppress_reason = is_suppressed(event, suppression_rules)
    if suppressed:
        print(f"[detection_orchestrator] Event suppressed: {suppress_reason}")
        return enrich_mitre(build_suppressed_detection(event, suppress_reason))
    # ──────────────────────────────────────────────────────────────────────────

    event = run_anomaly(event)
    event = run_threat_analysis(event)
    event = run_ioc_enrichment(event)
    event = run_correlation(event)
    event = fuse_detection(event)

    # Stamp ATT&CK once the verdict is known — downstream layers and the
    # campaign correlator both read from it.
    event = enrich_mitre(event)
    return event


def run_detection_batch(events: list[dict]) -> dict:
    # Load suppression rules once per batch for efficiency
    suppression_rules = load_suppression_rules()
    if suppression_rules:
        print(f"[detection_orchestrator] Loaded {len(suppression_rules)} FP suppression rule(s).")

    return {
        "status": "success",
        "detections": [run_detection(event, suppression_rules) for event in events]
    }