from .confidence_adjuster import adjust_confidence
from .cross_layer_matcher import match_cross_layer_signals
from .signal_collector import collect_signals


def run_correlation(event: dict) -> dict:
    signal_data = collect_signals(event)
    matched_result = match_cross_layer_signals(signal_data)
    adjusted = adjust_confidence(event, matched_result)

    event["correlation_analysis"] = {
        "correlated": matched_result.get("correlated", False),
        "correlation_strength": matched_result.get("correlation_strength", "none"),
        "signal_count": matched_result.get("signal_count", 0),
        "supporting_signals": matched_result.get("supporting_signals", []),
        "reasoning": matched_result.get("reasons", []),
        "adjusted_confidence": adjusted.get("adjusted_confidence", 0.0)
    }

    return event
