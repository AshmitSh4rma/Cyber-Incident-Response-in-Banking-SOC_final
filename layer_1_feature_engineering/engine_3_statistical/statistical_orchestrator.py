# statistical_orchestrator.py
#
# PURPOSE:
# Coordinates Engine 3 — Statistical.
# Calls frequency_analyzer then pattern_detector.
# Returns log with frequency_features and pattern_features added.
#
# CALLED BY:
# feature_orchestrator.py → _safe_run(run_statistical, log)


from layer_1_feature_engineering.engine_3_statistical.frequency_analyzer import (
    analyze_frequency,
)
from layer_1_feature_engineering.engine_3_statistical.pattern_detector import (
    detect_patterns,
)


def _safe_run(fn, log: dict, step_name: str) -> dict:
    try:
        return fn(log)
    except Exception as e:
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": "engine_3_statistical",
            "step":   step_name,
            "error":  str(e)
        })
        return {**log, "feature_errors": errors}


def run_statistical(log: dict) -> dict:
    """
    Receives log dict with temporal and behavioral features already added.
    Runs frequency_analyzer then pattern_detector.
    Returns log with frequency_features and pattern_features added.
    """

    # ── Step 1: Frequency analysis ────────
    log = _safe_run(analyze_frequency, log, "frequency_analyzer")

    # ── Step 2: Pattern detection ─────────
    log = _safe_run(detect_patterns, log, "pattern_detector")

    return log
