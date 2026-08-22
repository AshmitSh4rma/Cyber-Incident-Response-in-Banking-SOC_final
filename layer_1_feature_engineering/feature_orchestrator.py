# feature_orchestrator.py
#
# PURPOSE:
# The main coordinator of Layer 1.
# Receives the normalized log dict from the ingestion layer,
# runs it through all engines in the correct sequence,
# and returns the fully feature-enriched dict to the detection layer.
#
# FLOW:
# 1. classify_log()         → stamps log_family
# 2. temporal_orchestrator  → adds temporal_features
# 3. behavioral_orchestrator → adds behavioral_features
# 4. statistical_orchestrator → adds statistical_features
# 5. family-specific engine  → adds network/web/iot features
#
# ERROR HANDLING:
# Pass-through pattern — if any engine fails, the log passes through
# unchanged with an error note. Pipeline never breaks.
#
# CALLED BY:
# main.py or the ingestion layer output handler


from layer_1_feature_engineering.engine_1_temporal.temporal_orchestrator import (
    run_temporal,
)
from layer_1_feature_engineering.engine_2_behavioral.behavioral_orchestrator import (
    run_behavioral,
)
from layer_1_feature_engineering.engine_3_statistical.statistical_orchestrator import (
    run_statistical,
)
from layer_1_feature_engineering.engine_4_network.network_orchestrator import (
    run_network,
)
from layer_1_feature_engineering.engine_5_web.web_orchestrator import run_web
from layer_1_feature_engineering.engine_6_iot.iot_orchestrator import run_iot
from layer_1_feature_engineering.engine_7_identity.identity_orchestrator import (
    run_identity,
)
from layer_1_feature_engineering.log_classifier import classify_log

# ─────────────────────────────────────────
# HELPER — safe engine runner
# Wraps each engine call in try/except
# If engine fails, log passes through with error note
# ─────────────────────────────────────────

def _safe_run(engine_fn, log: dict, engine_name: str) -> dict:
    """
    Calls the engine function safely.
    On failure, returns the log unchanged with an error entry added.
    """
    try:
        return engine_fn(log)
    except Exception as e:
        # Do not break the pipeline
        # Stamp what went wrong and pass through
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": engine_name,
            "error": str(e)
        })
        return {**log, "feature_errors": errors}
def _should_run_identity(log: dict) -> bool:
    """
    Decide whether identity engine should run.

    We use source/event hints and a few known auth/risk fields.
    This is field-presence routing, so it works even when log_family is unknown.
    """
    raw_source = str(log.get("raw_source", "")).lower()
    event_type = str(log.get("event_type", "")).lower()
    additional_fields = log.get("additional_fields", {}) or {}
    raw_event = log.get("raw_event", {}) or {}

    event_id = raw_event.get("EventID", additional_fields.get("EventID", log.get("EventID")))

    identity_sources = {"azure_ad", "entra_id", "aad", "windows_security"}
    if raw_source in identity_sources:
        return True

    if "sign-in" in event_type or "signin" in event_type:
        return True

    if event_id in {4624, 4625, 4648, 4768, 4769, 4771, 4776}:
        return True

    hint_fields = [
        "UserPrincipalName",
        "UserId",
        "RiskState",
        "RiskLevel",
        "RiskEventTypes",
        "logon_type",
        "SubStatus",
        "auth_package",
    ]

    for field in hint_fields:
        if field in raw_event or field in additional_fields or field in log:
            return True

    return False

# ─────────────────────────────────────────
# MAIN ORCHESTRATOR FUNCTION
# Called once per log dict
# ─────────────────────────────────────────

def run_feature_engineering(log: dict) -> dict:
    """
    Receives a normalized log dict from ingestion.
    Returns the same dict enriched with all feature blocks.

    Always added:
        log_family
        classification_scores
        classification_confidence
        temporal_features
        behavioral_features
        statistical_features

    Conditionally added (based on log_family):
        network_features   ← if log_family == "network"
        web_features       ← if log_family == "web"
        iot_features       ← if log_family == "iot"
    """

    # ── Step 1: Classify ──────────────────
    log = _safe_run(classify_log, log, "log_classifier")

    # ── Step 2: Temporal (runs for ALL logs) ──
    log = _safe_run(run_temporal, log, "engine_1_temporal")

    # ── Step 3: Behavioral (runs for ALL logs) ──
    log = _safe_run(run_behavioral, log, "engine_2_behavioral")

    # ── Step 4: Statistical (runs for ALL logs) ──
    log = _safe_run(run_statistical, log, "engine_3_statistical")

        # ── Step 4.5: Identity engine (field-presence routing) ──
    if _should_run_identity(log):
        log = _safe_run(run_identity, log, "engine_7_identity")

    # ── Step 5: Family-specific engine ────
    family = log.get("log_family", "unknown")

    if family == "network":
        log = _safe_run(run_network, log, "engine_4_network")

    elif family == "web":
        log = _safe_run(run_web, log, "engine_5_web")

    elif family == "iot":
        log = _safe_run(run_iot, log, "engine_6_iot")

    else:
        # Unknown family — no family-specific engine runs
        # Log it so the analyst knows
        warnings = log.get("feature_warnings", [])
        warnings.append("log_family is unknown — family-specific features skipped")
        log = {**log, "feature_warnings": warnings}

    return log
