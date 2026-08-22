# iot_orchestrator.py
#
# PURPOSE:
# Coordinates Engine 6 — IoT.
# Runs device_profiler then telemetry_analyzer.
# Only called when log_family == "iot".
#
# CALLED BY:
# feature_orchestrator.py → _safe_run(run_iot, log)


from layer_1_feature_engineering.engine_6_iot.device_profiler import profile_device
from layer_1_feature_engineering.engine_6_iot.telemetry_analyzer import (
    analyze_telemetry,
)


def _safe_run(fn, log: dict, step_name: str) -> dict:
    try:
        return fn(log)
    except Exception as e:
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": "engine_6_iot",
            "step":   step_name,
            "error":  str(e)
        })
        return {**log, "feature_errors": errors}


def run_iot(log: dict) -> dict:
    """
    Receives log dict already enriched by engines 1, 2, 3.
    Runs device_profiler then telemetry_analyzer.
    Returns log with iot_device_features and
    iot_telemetry_features added.
    """

    # ── Step 1: Device profiling ──────────
    log = _safe_run(profile_device, log, "device_profiler")

    # ── Step 2: Telemetry analysis ────────
    log = _safe_run(analyze_telemetry, log, "telemetry_analyzer")

    return log
