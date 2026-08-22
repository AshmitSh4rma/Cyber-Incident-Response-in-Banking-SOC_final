"""Standalone FastAPI application for the SENTRA chatbot prototype."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from db_manager import check_database_health, close_db, init_db
from prototype_ai_chat.chat_service import ChatService
from prototype_ai_chat.schemas import ChatRequest, ChatResponse, HealthResponse

service = ChatService()
STATIC_DIR = Path(__file__).resolve().parent / "static"
_database_ready = False


def _initialize_database() -> bool:
    global _database_ready
    try:
        init_db()
        _database_ready = check_database_health()
    except Exception:
        _database_ready = False
    return _database_ready


def _database_connected() -> bool:
    global _database_ready
    # A transient health failure must never close/rebuild the process-wide pool;
    # lifespan exclusively owns pool open/close. Psycopg replaces stale checked
    # connections on the next bounded acquisition.
    try:
        _database_ready = check_database_health()
    except Exception:
        _database_ready = False
    return _database_ready


@asynccontextmanager
async def lifespan(_: FastAPI):
    _initialize_database()
    try:
        yield
    finally:
        close_db()
        await service.close()


app = FastAPI(title="SENTRA AI Log Analyst Prototype", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    database = "connected" if _database_connected() else "unavailable"
    gemini = service.gemini_status
    status = "ok" if database == "connected" and gemini == "available" else "degraded"
    return HealthResponse(status=status, database=database, gemini=gemini, model=service.model)


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    try:
        return await service.chat(request.message, request.session_id)
    except Exception as exc:
        if exc.__class__.__module__.startswith(("psycopg", "psycopg_pool", "database")):
            raise HTTPException(status_code=503, detail="SENTRA database is unavailable.") from None
        raise HTTPException(status_code=500, detail="The chatbot request could not be completed.") from None


@app.delete("/sessions/{session_id}")
def delete_session(session_id: str) -> dict[str, bool]:
    return {"deleted": service.delete_session(session_id)}
