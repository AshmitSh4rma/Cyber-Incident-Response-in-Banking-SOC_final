# network_orchestrator.py
#
# PURPOSE:
# Coordinates Engine 4 — Network.
# Runs traffic_analyzer then protocol_profiler.
# Only called when log_family == "network".
#
# CALLED BY:
# feature_orchestrator.py → _safe_run(run_network, log)


from layer_1_feature_engineering.engine_4_network.protocol_profiler import (
    profile_protocol,
)
from layer_1_feature_engineering.engine_4_network.traffic_analyzer import (
    analyze_traffic,
)


def _safe_run(fn, log: dict, step_name: str) -> dict:
    try:
        return fn(log)
    except Exception as e:
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": "engine_4_network",
            "step":   step_name,
            "error":  str(e)
        })
        return {**log, "feature_errors": errors}


def run_network(log: dict) -> dict:
    """
    Receives log dict already enriched by engines 1, 2, 3.
    Runs traffic_analyzer then protocol_profiler.
    Returns log with network_traffic_features and
    network_protocol_features added.
    """

    # ── Step 1: Traffic analysis ──────────
    log = _safe_run(analyze_traffic, log, "traffic_analyzer")

    # ── Step 2: Protocol profiling ────────
    log = _safe_run(profile_protocol, log, "protocol_profiler")

    return log
