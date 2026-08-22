# behavioral_orchestrator.py
#
# PURPOSE:
# Coordinates Engine 2 — Behavioral.
# Calls user_profiler first, then baseline_comparator.
# Returns the log with user_profile and behavioral_features added.
#
# ORDER MATTERS:
# baseline_comparator reads user_profile block.
# user_profiler must run first.
#
# CALLED BY:
# feature_orchestrator.py → _safe_run(run_behavioral, log)


from layer_1_feature_engineering.engine_2_behavioral.baseline_comparator import (
    compare_to_baseline,
)
from layer_1_feature_engineering.engine_2_behavioral.user_profiler import (
    build_user_profile,
)


def _safe_run(fn, log: dict, step_name: str) -> dict:
    try:
        return fn(log)
    except Exception as e:
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": "engine_2_behavioral",
            "step":   step_name,
            "error":  str(e)
        })
        return {**log, "feature_errors": errors}


def run_behavioral(log: dict) -> dict:
    """
    Receives log dict with time_windows and temporal_features already added.
    Runs user_profiler then baseline_comparator.
    Returns log with user_profile and behavioral_features added.
    """

    # ── Step 1: Build user profile ────────
    log = _safe_run(build_user_profile, log, "user_profiler")

    # ── Step 2: Compare to baseline ───────
    log = _safe_run(compare_to_baseline, log, "baseline_comparator")

    return log
