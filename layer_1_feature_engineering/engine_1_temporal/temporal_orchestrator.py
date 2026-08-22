# temporal_orchestrator.py
#
# PURPOSE:
# Coordinates Engine 1 — Temporal.
# Calls time_window_builder first, then tsfresh_extractor.
# Returns the fully temporal-enriched log dict.
#
# WHY THE ORDER MATTERS:
# tsfresh_extractor reads the timestamp field directly but the
# time_windows block built by time_window_builder gives it
# richer context — specifically the parsed datetime and window labels.
# Builder must always run before extractor.
#
# ERROR HANDLING:
# Same pass-through pattern as feature_orchestrator.
# If either sub-file fails, log passes through with error noted.
#
# CALLED BY:
# feature_orchestrator.py → _safe_run(run_temporal, log)


from layer_1_feature_engineering.engine_1_temporal.time_window_builder import (
    build_time_windows,
)
from layer_1_feature_engineering.engine_1_temporal.tsfresh_extractor import (
    extract_temporal_features,
)

# ─────────────────────────────────────────
# HELPER — safe runner
# Mirrors the pattern in feature_orchestrator
# Keeps error handling consistent across all layers
# ─────────────────────────────────────────

def _safe_run(fn, log: dict, step_name: str) -> dict:
    """
    Calls fn(log) safely.
    On failure stamps the error and passes the log through unchanged.
    """
    try:
        return fn(log)
    except Exception as e:
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": "engine_1_temporal",
            "step":   step_name,
            "error":  str(e)
        })
        return {**log, "feature_errors": errors}


# ─────────────────────────────────────────
# MAIN ORCHESTRATOR FUNCTION
# ─────────────────────────────────────────

def run_temporal(log: dict) -> dict:
    """
    Receives the classified log dict from feature_orchestrator.
    Runs time_window_builder then tsfresh_extractor in sequence.
    Returns the log dict with two new blocks added:

        time_windows        ← from time_window_builder
        temporal_features   ← from tsfresh_extractor

    Both blocks are always present after this function runs,
    even if one step failed (failed step leaves its block absent
    and stamps feature_errors instead).
    """

    # ── Step 1: Build time windows ────────
    log = _safe_run(build_time_windows, log, "time_window_builder")

    # ── Step 2: Extract temporal features ─
    log = _safe_run(extract_temporal_features, log, "tsfresh_extractor")

    return log
