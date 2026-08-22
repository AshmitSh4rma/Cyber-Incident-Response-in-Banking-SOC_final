from .pattern_mapper import map_threat_patterns
from .threat_classifier import classify_threat


def run_threat_analysis(event: dict) -> dict:
    mapped = map_threat_patterns(event)
    classified = classify_threat(mapped)

    event["threat_analysis"] = {
        "matched_patterns": mapped.get("matched_patterns", []),
        "mapped_pattern": classified.get("threat_type"),
        "severity": classified.get("severity"),
        "confidence": classified.get("confidence"),
        "reasoning": classified.get("reasoning"),
    }

    return event
