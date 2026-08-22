# web_orchestrator.py
#
# PURPOSE:
# Coordinates Engine 5 — Web.
# Runs http_analyzer then session_profiler.
# Only called when log_family == "web".
#
# CALLED BY:
# feature_orchestrator.py → _safe_run(run_web, log)


from layer_1_feature_engineering.engine_5_web.http_analyzer import analyze_http
from layer_1_feature_engineering.engine_5_web.session_profiler import profile_session


def _safe_run(fn, log: dict, step_name: str) -> dict:
    try:
        return fn(log)
    except Exception as e:
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": "engine_5_web",
            "step":   step_name,
            "error":  str(e)
        })
        return {**log, "feature_errors": errors}


def run_web(log: dict) -> dict:
    """
    Receives log dict already enriched by engines 1, 2, 3.
    Runs http_analyzer then session_profiler.
    Returns log with web_http_features and
    web_session_features added.
    """

    # ── Step 1: HTTP analysis ─────────────
    log = _safe_run(analyze_http, log, "http_analyzer")

    # ── Step 2: Session profiling ─────────
    log = _safe_run(profile_session, log, "session_profiler")

    return log
