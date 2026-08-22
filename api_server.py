"""
SENTRA SOC API.

Serves the analyst dashboard and runs the pipeline over uploaded logs. The
pipeline itself lives in pipeline.py so the CLI and the API cannot drift apart.
"""

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, File, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

import soc_config
from audit_report import campaign_report, incident_report
from db_manager import (
    clear_all_incidents,
    decide_approval,
    get_all_campaigns,
    get_all_incidents,
    get_approvals,
    get_campaign,
    get_feedback_for_incident,
    get_incident,
    get_suppression_list,
    init_db,
    replace_campaigns,
    request_approval,
    save_feedback,
    save_incident,
    update_incident_status,
)
from layer_1_feature_engineering.ingestion_orchestrator import (
    process_json_text,
    process_jsonl_text,
)
from pipeline import isolated_state, run_full_pipeline
from regulatory_clock import REGIMES, for_campaign, for_incident, format_remaining
from soc_metrics import compute_metrics

BASE_DIR = Path(__file__).resolve().parent

# Both copies stay in step. dev_run.py writes both, so if the API wrote only one
# the repo-root copy would silently go stale.
OUTPUT_PATHS = (
    BASE_DIR / "Frontend" / "public" / "frontend_output.json",
    BASE_DIR / "frontend_output.json",
)
METRICS_PATH = BASE_DIR / "Frontend" / "public" / "soc_metrics.json"

MAX_UPLOAD_RECORDS = 5000

# Wall-clock of the most recent pipeline run, surfaced in /api/metrics.
_LAST_RUN_SECONDS: float | None = None


def _last_run_seconds() -> float | None:
    """
    Duration of the most recent pipeline run.

    Prefers a run in this process, then falls back to the timing block in the
    output file — otherwise a freshly-started server reports no latency at all
    even though the shipped demo data was produced by a real run, and the
    dashboard renders a blank metric.
    """
    if _LAST_RUN_SECONDS is not None:
        return _LAST_RUN_SECONDS
    try:
        with open(OUTPUT_PATHS[1], encoding="utf-8") as f:
            return (json.load(f).get("timing") or {}).get("total")
    except Exception:
        return None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    print("[api_server] Initializing SQLite database...")
    init_db()
    yield


app = FastAPI(
    title="SENTRA SOC API",
    description="Automated incident response pipeline for banking security operations.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Service
# ─────────────────────────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def _normalise_validation_errors(_request: Request, exc: RequestValidationError):
    """
    Give FastAPI's own 422 the same shape as ours.

    Framework validation answers {"detail": [...]}, which carries neither
    `message` nor `errors`. The settings console reads both, so a malformed body
    produced a rejection banner reading "Fix the 0 marked below" with nothing
    marked. One documented 422 shape, whoever generated it.
    """
    errors: dict[str, str] = {}
    for item in exc.errors():
        location = ".".join(str(part) for part in item.get("loc", ()) if part != "body") or "_"
        errors[location] = str(item.get("msg", "Invalid value."))

    return JSONResponse(
        status_code=422,
        content={
            "status": "invalid",
            "message": f"{len(errors)} field{'s' if len(errors) != 1 else ''} "
                       "could not be read. Nothing was saved.",
            "errors": errors,
        },
    )


@app.get("/")
async def root():
    """Service banner and endpoint index."""
    return {
        "status": "ok",
        "service": "SENTRA SOC API",
        "version": "2.0.0",
        "docs": "/docs",
        "endpoints": {
            "pipeline": ["POST /run-pipeline"],
            "incidents": [
                "GET /api/incidents",
                "GET /api/incidents/{event_id}",
                "POST /api/incidents/{event_id}/action",
                "DELETE /api/incidents",
            ],
            "campaigns": ["GET /api/campaigns", "GET /api/campaigns/{campaign_id}"],
            "metrics": ["GET /api/metrics"],
            "compliance": ["GET /api/notifications", "GET /api/regimes"],
            "feedback": [
                "POST /api/incidents/{event_id}/feedback",
                "GET /api/incidents/{event_id}/feedback",
                "GET /api/suppression-rules",
            ],
            "approvals": [
                "GET /api/approvals",
                "POST /api/incidents/{event_id}/approvals",
                "POST /api/approvals/{approval_id}/decision",
            ],
            "reports": [
                "GET /api/incidents/{event_id}/report",
                "GET /api/campaigns/{campaign_id}/report",
            ],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/run-pipeline")
async def run_pipeline(file: UploadFile = File(...)):
    """Ingest a JSON or JSONL log file and run every layer over it."""
    global _LAST_RUN_SECONDS

    content = await file.read()

    if not content or not content.strip():
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Uploaded file is empty. Provide a JSON array of log records."},
        )

    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "File is not valid UTF-8 text. Upload a JSON or JSONL log file."},
        )

    try:
        normalized = process_json_text(content_str)
    except ValueError as json_err:
        try:
            normalized = process_jsonl_text(content_str)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": f"Could not parse the uploaded file as JSON or JSONL. {json_err}",
                },
            )

    if not normalized:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "No log records found in the uploaded file."},
        )

    if len(normalized) > MAX_UPLOAD_RECORDS:
        return JSONResponse(
            status_code=413,
            content={
                "status": "error",
                "message": f"File contains {len(normalized)} records; the limit is {MAX_UPLOAD_RECORDS}.",
            },
        )

    # Each submitted batch is analysed on its own merits.
    #
    # Layer 1 accumulates per-source history — unique ports seen per address,
    # failed logins per account, byte ratios — in module state, and none of it
    # decays. Without isolation the same file scored differently on every upload:
    # by the second replay of the demo scenario the four benign records had been
    # dragged over the port-scan and brute-force thresholds by their own earlier
    # selves, and the benign class collapsed to zero. A verdict that depends on
    # how many times you pressed the button is not a verdict.
    #
    # This is an ingestion endpoint for log *files*, so treating each batch as
    # self-contained is also the honest semantic: the alternative is cross-batch
    # counters with no time window, which in a real deployment means an address
    # that scanned fifteen ports last year still counts today.
    started = time.perf_counter()
    with isolated_state():
        output = run_full_pipeline(normalized)
    _LAST_RUN_SECONDS = time.perf_counter() - started

    events = output["events"]
    campaigns = output["campaigns"]

    for event in events:
        save_incident(event)
    replace_campaigns(campaigns)

    for output_path in OUTPUT_PATHS:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

    return {
        "status": "success",
        "events": len(events),
        "campaigns": len(campaigns),
        "campaign_summary": output.get("campaign_summary", {}),
        "seconds": round(_LAST_RUN_SECONDS, 3),
        "timing": output.get("timing", {}),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Incidents
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/incidents")
async def list_incidents():
    return get_all_incidents()


@app.get("/api/incidents/{event_id}")
async def read_incident(event_id: str):
    incident = get_incident(event_id)
    if not incident:
        return JSONResponse(status_code=404, content={"message": "Incident not found"})
    return incident


@app.post("/api/incidents/{event_id}/action")
async def trigger_action(event_id: str, payload: dict = Body(...)):
    action = payload.get("action")
    status = "open"

    if action in ["close", "false_positive", "contain", "Closed"]:
        status = "closed"
    elif action in ["escalate", "true_positive", "Investigate", "investigating", "Investigating"]:
        status = "investigating"

    if not update_incident_status(event_id, status):
        return JSONResponse(status_code=404, content={"message": "Incident not found"})

    return {"status": "success", "incidentId": event_id, "action": action, "currentStatus": status}


@app.delete("/api/incidents")
async def delete_incidents():
    clear_all_incidents()
    replace_campaigns([])
    return {"status": "success", "message": "All incidents and campaigns cleared"}


# ─────────────────────────────────────────────────────────────────────────────
# Campaigns (Layer 2.5)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/campaigns")
async def list_campaigns():
    """Correlated attack campaigns, worst progression first."""
    campaigns = get_all_campaigns()
    return {"count": len(campaigns), "campaigns": campaigns}


@app.get("/api/campaigns/{campaign_id}")
async def read_campaign(campaign_id: str):
    campaign = get_campaign(campaign_id)
    if not campaign:
        return JSONResponse(status_code=404, content={"message": "Campaign not found"})

    # Attach member incidents so the UI needs one round trip, not N.
    by_id = {i.get("event_id"): i for i in get_all_incidents()}
    campaign["incidents"] = [by_id[i] for i in campaign.get("incident_ids", []) if i in by_id]
    return campaign


# ─────────────────────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/metrics")
async def metrics():
    """SOC value metrics computed from stored state, not asserted."""
    incidents = get_all_incidents()
    campaigns = get_all_campaigns()

    feedback: list[dict] = []
    for incident in incidents:
        feedback.extend(get_feedback_for_incident(incident.get("event_id", "")))

    return compute_metrics(incidents, campaigns, feedback, _last_run_seconds())



# ─────────────────────────────────────────────────────────────────────────────
# Regulatory notification clocks
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/regimes")
async def list_regimes():
    """The notification regimes and their deadlines, with the instrument for each."""
    return {"count": len(REGIMES), "regimes": REGIMES}


@app.get("/api/notifications")
async def notifications():
    """
    Everything currently carrying a notification deadline, soonest first.

    Recomputed on read rather than stored, because the whole value of this view is
    that the countdown is live. A campaign is one incident to a regulator, so
    campaigns are the primary unit and standalone incidents are only included when
    they belong to no campaign.
    """
    campaigns = get_all_campaigns()
    incidents = get_all_incidents()

    in_campaign: set[str] = set()
    for campaign in campaigns:
        in_campaign.update(campaign.get("incident_ids", []))

    items = []

    for campaign in campaigns:
        clock = for_campaign(campaign)
        if not clock["reportable"]:
            continue
        items.append(
            {
                "kind": "campaign",
                "id": campaign.get("campaign_id"),
                "title": campaign.get("name"),
                "severity": campaign.get("severity"),
                "stage": campaign.get("furthest_stage"),
                "alert_count": campaign.get("incident_count"),
                "notification": clock,
            }
        )

    for incident in incidents:
        if incident.get("event_id") in in_campaign:
            continue
        clock = for_incident(incident)
        if not clock["reportable"]:
            continue
        detection = incident.get("detection") or {}
        dash = incident.get("dashboard") or {}
        items.append(
            {
                "kind": "incident",
                "id": incident.get("event_id"),
                "title": dash.get("alert_title") or detection.get("threat_type"),
                "severity": detection.get("severity"),
                "stage": (incident.get("mitre_attack") or {}).get("kill_chain_stage"),
                "alert_count": 1,
                "notification": clock,
            }
        )

    items.sort(key=lambda i: i["notification"]["tightest"]["deadline"])

    for item in items:
        for clock in item["notification"]["clocks"]:
            clock["remaining_label"] = format_remaining(clock["seconds_remaining"])

    overdue = sum(
        1 for i in items if any(c["state"] == "overdue" for c in i["notification"]["clocks"])
    )

    return {
        "count": len(items),
        "overdue": overdue,
        "tightest_deadline": items[0]["notification"]["tightest"]["deadline"] if items else None,
        "items": items,
        "disclaimer": (
            "Decision support, not a compliance filing and not legal advice. The "
            "institution's compliance function makes the determination and owns the filing."
        ),
    }

# ─────────────────────────────────────────────────────────────────────────────
# Analyst feedback / suppression
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/incidents/{event_id}/feedback")
async def submit_feedback(event_id: str, payload: dict = Body(...)):
    """
    Record analyst feedback. A false_positive also writes a suppression rule that
    Layer 2 consults before running any engine on the next batch.
    """
    label = payload.get("label", "")
    reason = payload.get("reason", "")
    analyst_notes = payload.get("analyst_notes", "")

    valid_labels = {"true_positive", "false_positive", "false_negative", "escalated"}
    if label not in valid_labels:
        return JSONResponse(
            status_code=400,
            content={"message": f"Invalid label. Must be one of: {', '.join(sorted(valid_labels))}"},
        )

    incident = get_incident(event_id)
    if not incident:
        return JSONResponse(status_code=404, content={"message": "Incident not found"})

    dashboard = incident.get("dashboard") or {}
    detection = incident.get("detection") or {}
    raw_event = incident.get("raw_event") or {}

    source_ip = dashboard.get("source_ip") or raw_event.get("source_ip")
    threat_type = detection.get("threat_type") or dashboard.get("threat_type")
    affected_user = dashboard.get("affected_user") or raw_event.get("user")

    save_feedback(
        event_id=event_id,
        label=label,
        reason=reason,
        analyst_notes=analyst_notes,
        source_ip=source_ip,
        threat_type=threat_type,
        affected_user=affected_user,
    )

    status_map = {
        "true_positive": "investigating",
        "false_positive": "closed",
        "false_negative": "investigating",
        "escalated": "investigating",
    }
    update_incident_status(event_id, status_map[label])

    suppression_note = ""
    if label == "false_positive":
        suppression_note = (
            f" A suppression rule now covers source_ip={source_ip}, threat_type={threat_type}; "
            "matching events are short-circuited on the next pipeline run."
        )

    return {
        "status": "success",
        "incidentId": event_id,
        "label": label,
        "reason": reason,
        "suppression_created": label == "false_positive",
        "message": f"Feedback recorded as {label}.{suppression_note}",
    }


@app.get("/api/incidents/{event_id}/feedback")
async def get_incident_feedback(event_id: str):
    return get_feedback_for_incident(event_id)


@app.get("/api/suppression-rules")
async def list_suppression_rules():
    rules = get_suppression_list()
    return {"count": len(rules), "rules": rules}


# ─────────────────────────────────────────────────────────────────────────────
# Human-in-the-loop response approvals
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/approvals")
async def list_approvals(state: str | None = None):
    """Containment actions queued for analyst sign-off."""
    approvals = get_approvals(state=state)
    return {"count": len(approvals), "approvals": approvals}


@app.post("/api/incidents/{event_id}/approvals")
async def create_approval(event_id: str, payload: dict = Body(...)):
    """Queue one containment action for approval."""
    action = str(payload.get("action") or "").strip()
    if not action:
        return JSONResponse(status_code=400, content={"message": "An 'action' is required."})

    if not get_incident(event_id):
        return JSONResponse(status_code=404, content={"message": "Incident not found"})

    approval_id = request_approval(event_id, action)
    return {"status": "pending", "approval_id": approval_id, "event_id": event_id, "action": action}


@app.post("/api/approvals/{approval_id}/decision")
async def decide(approval_id: int, payload: dict = Body(...)):
    """Approve or reject a queued containment action."""
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in {"approve", "reject"}:
        return JSONResponse(status_code=400, content={"message": "decision must be 'approve' or 'reject'"})

    ok = decide_approval(
        approval_id,
        approve=decision == "approve",
        decided_by=payload.get("decided_by") or "analyst",
        note=payload.get("note") or "",
    )
    if not ok:
        return JSONResponse(status_code=404, content={"message": "No pending approval with that id"})

    return {"status": "success", "approval_id": approval_id, "decision": decision}


# ─────────────────────────────────────────────────────────────────────────────
# Audit reports
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/incidents/{event_id}/report", response_class=PlainTextResponse)
async def incident_audit_report(event_id: str):
    """The incident as a self-contained Markdown audit record."""
    incident = get_incident(event_id)
    if not incident:
        return PlainTextResponse("Incident not found", status_code=404)

    return PlainTextResponse(
        incident_report(incident),
        headers={"Content-Disposition": f'attachment; filename="incident-{event_id}.md"'},
    )


@app.get("/api/campaigns/{campaign_id}/report", response_class=PlainTextResponse)
async def campaign_audit_report(campaign_id: str):
    """The campaign and its member incidents as one Markdown report."""
    campaign = get_campaign(campaign_id)
    if not campaign:
        return PlainTextResponse("Campaign not found", status_code=404)

    return PlainTextResponse(
        campaign_report(campaign, get_all_incidents()),
        headers={"Content-Disposition": f'attachment; filename="campaign-{campaign_id}.md"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
#
# The whole point of these endpoints is that a bank should not need a developer
# to change its own risk appetite. Two things make that safe rather than merely
# possible:
#
#   - Nothing is written unless the entire patch validates. Field errors come
#     back keyed by setting, so the console renders each against its control
#     rather than showing one banner and losing the rest.
#   - A change can be previewed before it is kept. `/api/config/preview` runs the
#     pipeline twice over the same records — once as configured, once with the
#     candidate applied — and returns both, so "what will this do" is answered
#     with numbers rather than a guess.
# ─────────────────────────────────────────────────────────────────────────────

_DEMO_SCENARIO = Path(__file__).resolve().parent / "demo_attack_scenario.json"


def _outcome(output: dict) -> dict:
    """
    The handful of numbers that tell an operator whether a config change did what
    they wanted. Deliberately the same shape for the before and after side, so the
    console can diff them without knowing what any of them mean.
    """
    events = output.get("events", []) or []
    campaigns = output.get("campaigns", []) or []

    actionable = [
        e for e in events
        if str((e.get("detection") or {}).get("label", "")).lower() not in ("benign", "suppressed")
    ]

    severity: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    for event in actionable:
        detection = event.get("detection") or {}
        key = str(detection.get("severity", "unknown")).lower()
        severity[key] = severity.get(key, 0) + 1
        verdict = str(detection.get("label", "unknown")).lower()
        verdicts[verdict] = verdicts.get(verdict, 0) + 1

    auto = gated = 0
    for event in events:
        for step in (event.get("response") or {}).get("containment_plan", []) or []:
            if step.get("execution") == "auto":
                auto += 1
            else:
                gated += 1

    reportable = 0
    clocks = 0
    for campaign in campaigns:
        notification = campaign.get("notification") or {}
        if notification.get("reportable") is True:
            reportable += 1
            clocks += len(notification.get("clocks") or [])

    metrics = compute_metrics(events, campaigns)

    return {
        "alerts": len(events),
        "actionable": len(actionable),
        "filtered_out": len(events) - len(actionable),
        "severity": severity,
        "verdicts": verdicts,
        "campaigns": len(campaigns),
        "investigations": (metrics.get("consolidation") or {}).get("investigations"),
        "reportable_campaigns": reportable,
        "notification_deadlines": clocks,
        "actions_automatic": auto,
        "actions_needing_approval": gated,
        "hours_saved": (metrics.get("time") or {}).get("hours_saved"),
    }


def _run_demo_scenario() -> dict | None:
    """
    Run the canonical demo records through every layer, in isolation.

    Layer 1 accumulates per-source history in module state, which matters twice
    over. The two comparison runs must not see each other, or the second inherits
    the first one's traffic and the comparison measures the wrong thing — and
    neither of them may disturb what the live process had already learned, or a
    read-only "what if" would silently change how the next real upload is scored.
    """
    if not _DEMO_SCENARIO.exists():
        return None
    try:
        records = process_json_text(_DEMO_SCENARIO.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    with isolated_state():
        return run_full_pipeline(records)


@app.get("/api/config")
async def read_config():
    """The schema, the current values, what differs from default, and recent changes."""
    return soc_config.status()


@app.put("/api/config")
async def write_config(payload: dict = Body(...)):
    """
    Apply a change.

    Returns 422 with per-field messages if anything is invalid, and writes nothing
    in that case. On success the stored settings are live immediately — every layer
    reads them at the point of use — and the response says what changed.
    """
    patch = payload.get("values", payload) if isinstance(payload, dict) else None
    if not isinstance(patch, dict) or not patch:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Send an object of setting keys to new values."},
        )

    cleaned, errors = soc_config.validate(patch)
    if errors:
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid",
                "message": f"{len(errors)} setting{'s' if len(errors) != 1 else ''} "
                           "could not be applied. Nothing was saved.",
                "errors": errors,
            },
        )

    if not cleaned:
        return {"status": "success", "message": "Nothing to change.", "changes": [],
                **soc_config.status()}

    result = soc_config.save(cleaned, actor=str(payload.get("actor") or "console"))

    if not result["changes"]:
        return {"status": "success", "message": "Those values were already in effect.",
                "changes": [], **soc_config.status()}

    return {
        "status": "success",
        "message": f"Saved {len(result['changes'])} change"
                   f"{'s' if len(result['changes']) != 1 else ''}. "
                   "Re-run the pipeline to score existing alerts with the new settings.",
        "changes": result["changes"],
        **soc_config.status(),
    }


@app.post("/api/config/reset")
async def reset_config():
    """Return every setting to its shipped default."""
    result = soc_config.reset()
    count = len(result["changes"])
    return {
        "status": "success",
        "message": "Already at defaults." if not count else
                   f"Reset {count} setting{'s' if count != 1 else ''} to default.",
        "changes": result["changes"],
        **soc_config.status(),
    }


@app.post("/api/config/preview")
async def preview_config(payload: dict = Body(...)):
    """
    What would this change do?

    Runs the demo records twice — as configured, then with the candidate applied —
    and returns both outcomes plus the difference. Nothing is saved.

    One honest caveat: the preview holds the candidate settings in process state
    for the duration of the run, so two previews at the same instant would
    interfere. That is acceptable for a console one operator drives, and saying so
    is better than pretending otherwise.
    """
    patch = payload.get("values", payload) if isinstance(payload, dict) else None
    if not isinstance(patch, dict) or not patch:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Send an object of setting keys to new values."},
        )

    cleaned, errors = soc_config.validate(patch)
    if errors:
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid",
                "message": "Cannot preview a configuration that would not be accepted.",
                "errors": errors,
            },
        )

    # A console default has no pipeline effect by construction. Running the
    # pipeline anyway and reporting "no measurable difference" reads as "this
    # control does nothing", which is the opposite of true.
    if all(soc_config.SETTINGS_BY_KEY[k]["group"] == "views" for k in cleaned):
        return {
            "status": "success",
            "message": "This changes what the console shows, not how alerts are scored — "
                       "so there is nothing to re-run. Save it and the change is visible "
                       "on your next visit.",
            "source": None,
            "candidate": cleaned,
            "before": None,
            "after": None,
            "differences": [],
        }

    baseline = _run_demo_scenario()
    if baseline is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "message": "No demo records available to preview against. "
                           "Replay a scenario from Simulation first.",
            },
        )
    before = _outcome(baseline)

    # Summarised inside the block, not after it: several of these figures are
    # themselves computed from configuration (hours saved from the minutes model,
    # the clock count from the regime list), so measuring them once the candidate
    # has been withdrawn reports the old value and hides the effect.
    with soc_config.previewing(cleaned):
        candidate = _run_demo_scenario()
        after = _outcome(candidate) if candidate else before

    # Both nested maps are compared whole rather than key-by-key, so a shift
    # between two bands reads as one change rather than two.
    nested = ("severity", "verdicts")
    differences = [
        {"metric": key, "before": before[key], "after": after[key]}
        for key in before
        if key not in nested and before[key] != after.get(key)
    ]
    differences += [
        {"metric": key, "before": before[key], "after": after[key]}
        for key in nested
        if before[key] != after[key]
    ]

    return {
        "status": "success",
        "message": (
            "No measurable difference on the demo records."
            if not differences
            else f"{len(differences)} figure{'s' if len(differences) != 1 else ''} would change."
        ),
        "source": _DEMO_SCENARIO.name,
        "candidate": cleaned,
        "before": before,
        "after": after,
        "differences": differences,
    }
