from fastapi import FastAPI, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import json
from contextlib import asynccontextmanager
from pathlib import Path

from layer_1_feature_engineering.ingestion_orchestrator import process_json_text, process_jsonl_text
from layer_2_detection.detection_orchestrator import run_detection_batch
from layer_3_cis.orchestrator import run_layer3
from frontend_formatter import format_pipeline_for_frontend
from layer_4_ai_analysis.incident_report_builder import run_layer4
from layer_5_cvss.cvss_orchestrator import run_cvss
from layer_6_response.response_orchestrator import run_response

from db_manager import (
    init_db,
    save_incident,
    get_all_incidents,
    get_incident,
    update_incident_status,
    clear_all_incidents,
    save_feedback,
    get_suppression_list,
    get_feedback_for_incident,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    print("[api_server] Initializing SQLite database...")
    init_db()
    yield


app = FastAPI(title="SENTRA SOC API Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent

# Keep both copies in step. dev_run.py writes both, so if the API only wrote the
# one under Frontend/public the repo-root copy would silently go stale and the two
# would disagree about what the last run produced.
OUTPUT_PATHS = (
    BASE_DIR / "Frontend" / "public" / "frontend_output.json",
    BASE_DIR / "frontend_output.json",
)

MAX_UPLOAD_RECORDS = 5000


@app.post("/run-pipeline")
async def run_pipeline(file: UploadFile = File(...)):
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

    # Layer 1 — accept JSON first, fall back to JSONL (one object per line).
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
                "message": f"File contains {len(normalized)} records; the limit is {MAX_UPLOAD_RECORDS}. Split the file and retry.",
            },
        )

    from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering
    layer1 = [run_feature_engineering(rec) for rec in normalized]

    # Layer 2
    layer2 = run_detection_batch(layer1)

    # Layer 3
    layer3 = run_layer3(layer2)

    # Frontend format
    frontend_output = format_pipeline_for_frontend(
        parsed_logs=None,
        layer1_output=layer1,
        layer2_output=layer2,
        layer3_output=layer3,
    )

    # Layer 4
    enriched = run_layer4(frontend_output["events"])

    for event in enriched:
        event["cvss"] = run_cvss(event["ai_analysis"])
        event["response"] = run_response(event)

    frontend_output["events"] = enriched

    # Save to SQLite Database
    for event in enriched:
        save_incident(event)

    # Save the static fallback copies used by the dashboard and by offline review.
    for output_path in OUTPUT_PATHS:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(frontend_output, f, indent=2, ensure_ascii=False)

    return {"status": "success", "events": len(enriched)}


@app.get("/")
async def root():
    """Service banner — confirms the API is up and points at the docs."""
    return {
        "status": "ok",
        "service": "SENTRA SOC API Backend",
        "docs": "/docs",
        "endpoints": [
            "POST /run-pipeline",
            "GET /api/incidents",
            "GET /api/incidents/{event_id}",
            "POST /api/incidents/{event_id}/action",
            "POST /api/incidents/{event_id}/feedback",
            "GET /api/incidents/{event_id}/feedback",
            "GET /api/suppression-rules",
            "POST /api/simulate",
            "DELETE /api/incidents",
        ],
    }

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
        
    success = update_incident_status(event_id, status)
    if not success:
        return JSONResponse(status_code=404, content={"message": "Incident not found"})
        
    return {
        "status": "success",
        "incidentId": event_id,
        "action": action,
        "currentStatus": status
    }

@app.post("/api/simulate")
async def simulate_events(payload: dict = Body(...)):
    events = payload.get("events", [])
    count = 0
    for event in events:
        if get_incident(event.get("event_id")):
            continue
        save_incident(event)
        count += 1
    return {"status": "success", "count": count}

@app.delete("/api/incidents")
async def delete_incidents():
    clear_all_incidents()
    return {"status": "success", "message": "All incidents cleared"}


@app.post("/api/incidents/{event_id}/feedback")
async def submit_feedback(event_id: str, payload: dict = Body(...)):
    """
    Record analyst feedback (TP/FP/FN/Escalated) for an incident.
    Extracts source_ip, threat_type, affected_user from the stored incident
    and persists them alongside the label/reason/notes in analyst_feedback table.
    If the label is false_positive, this also creates a suppression rule for future pipeline runs.
    """
    label = payload.get("label", "")
    reason = payload.get("reason", "")
    analyst_notes = payload.get("analyst_notes", "")

    valid_labels = {"true_positive", "false_positive", "false_negative", "escalated"}
    if label not in valid_labels:
        return JSONResponse(status_code=400, content={"message": f"Invalid label. Must be one of: {', '.join(valid_labels)}"})

    # Look up the incident to extract matching features for suppression
    incident = get_incident(event_id)
    if not incident:
        return JSONResponse(status_code=404, content={"message": "Incident not found"})

    dashboard = incident.get("dashboard") or {}
    detection = incident.get("detection") or {}

    source_ip     = dashboard.get("source_ip") or incident.get("raw_event", {}).get("source_ip")
    threat_type   = detection.get("threat_type") or dashboard.get("threat_type")
    affected_user = dashboard.get("affected_user") or incident.get("raw_event", {}).get("user")

    # Save the feedback record
    save_feedback(
        event_id=event_id,
        label=label,
        reason=reason,
        analyst_notes=analyst_notes,
        source_ip=source_ip,
        threat_type=threat_type,
        affected_user=affected_user,
    )

    # Update incident status based on label
    status_map = {
        "true_positive":  "investigating",
        "false_positive": "closed",
        "false_negative": "investigating",
        "escalated":      "investigating",
    }
    update_incident_status(event_id, status_map[label])

    suppression_note = ""
    if label == "false_positive":
        suppression_note = f" A suppression rule has been created for source_ip={source_ip}, threat_type={threat_type}."

    return {
        "status": "success",
        "incidentId": event_id,
        "label": label,
        "reason": reason,
        "suppression_created": label == "false_positive",
        "message": f"Feedback recorded as {label}.{suppression_note}"
    }


@app.get("/api/incidents/{event_id}/feedback")
async def get_incident_feedback(event_id: str):
    """Return the full analyst feedback history for an incident."""
    return get_feedback_for_incident(event_id)


@app.get("/api/suppression-rules")
async def list_suppression_rules():
    """Return all active False Positive suppression rules derived from analyst feedback."""
    rules = get_suppression_list()
    return {
        "count": len(rules),
        "rules": rules
    }