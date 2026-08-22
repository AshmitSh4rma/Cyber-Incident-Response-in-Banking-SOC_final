"""
SENTRA SOC API.

Serves the analyst dashboard and runs the pipeline over uploaded logs. The
pipeline itself lives in pipeline.py so the CLI and the API cannot drift apart.
"""

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from audit_report import campaign_report, incident_report
from layer_1_feature_engineering.ingestion_orchestrator import (
    process_json_text,
    process_jsonl_text,
)
from pipeline import run_full_pipeline
from regulatory_clock import REGIMES, for_campaign, for_incident, format_remaining
from soc_metrics import compute_metrics

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

    started = time.perf_counter()
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

    return compute_metrics(incidents, campaigns, feedback, _LAST_RUN_SECONDS)



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
