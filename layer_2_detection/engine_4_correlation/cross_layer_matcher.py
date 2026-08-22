def match_cross_layer_signals(signal_data: dict) -> dict:
    supporting_signals = signal_data.get("supporting_signals", []) or []

    signal_count = len(supporting_signals)

    if "anomaly_detected" in supporting_signals and "threat_pattern_identified" in supporting_signals and "ioc_match_found" in supporting_signals:
        correlation_strength = "strong"
        correlated = True
    elif signal_count >= 2:
        correlation_strength = "medium"
        correlated = True
    elif signal_count == 1:
        correlation_strength = "weak"
        correlated = True
    else:
        correlation_strength = "none"
        correlated = False

    return {
        "correlated": correlated,
        "correlation_strength": correlation_strength,
        "signal_count": signal_count,
        "supporting_signals": supporting_signals,
        "reasons": signal_data.get("reasons", []),
    }
