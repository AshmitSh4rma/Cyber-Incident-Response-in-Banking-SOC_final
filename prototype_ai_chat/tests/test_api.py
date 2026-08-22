import pytest
from fastapi.testclient import TestClient

from prototype_ai_chat import api
from prototype_ai_chat.schemas import ChatResponse


@pytest.fixture(autouse=True)
def isolate_database_lifecycle(monkeypatch):
    monkeypatch.setattr(api, "init_db", lambda: None)
    monkeypatch.setattr(api, "close_db", lambda: None)
    monkeypatch.setattr(api, "check_database_health", lambda: True)
    api._database_ready = False


def response(session_id="session_1", ai_used=True):
    return ChatResponse(
        answer="Grounded answer", intent="incident_count", evidence=[], records_considered=0,
        context_truncated=False, ai_used=ai_used, model="gemini-test", session_id=session_id,
    )


def test_health_connected_and_degraded(monkeypatch):
    monkeypatch.setattr(api, "_database_connected", lambda: True)
    monkeypatch.setattr(api.service, "gemini_status", "available")
    with TestClient(api.app) as client:
        body = client.get("/health").json()
    assert body["status"] == "ok" and body["database"] == "connected"

    monkeypatch.setattr(api, "_database_connected", lambda: False)
    monkeypatch.setattr(api.service, "gemini_status", "fallback")
    with TestClient(api.app) as client:
        body = client.get("/health").json()
    assert body["status"] == "degraded" and body["database"] == "unavailable"


def test_health_failure_never_closes_or_reinitializes_shared_pool(monkeypatch):
    calls = []
    monkeypatch.setattr(api, "check_database_health", lambda: False)
    monkeypatch.setattr(api, "close_db", lambda: calls.append("close"))
    monkeypatch.setattr(api, "init_db", lambda: calls.append("initialize"))
    assert api._database_connected() is False
    assert calls == []


def test_lifespan_initializes_and_closes_database(monkeypatch):
    calls = []
    monkeypatch.setattr(api, "_initialize_database", lambda: calls.append("initialize") or True)
    monkeypatch.setattr(api, "close_db", lambda: calls.append("close"))

    async def fake_close():
        calls.append("service_close")

    monkeypatch.setattr(api.service, "close", fake_close)
    with TestClient(api.app):
        assert calls == ["initialize"]
    assert calls == ["initialize", "close", "service_close"]


def test_root_page_and_static_assets_load():
    with TestClient(api.app) as client:
        page = client.get("/")
        script = client.get("/static/app.js")
        styles = client.get("/static/styles.css")
    assert page.status_code == 200
    assert "SENTRA AI Analyst" in page.text
    assert script.status_code == 200 and "POST" in script.text
    assert "appendInlineMarkdown" in script.text
    assert "innerHTML" not in script.text
    assert styles.status_code == 200 and ".conversation" in styles.text


def test_chat_validation_and_success(monkeypatch):
    async def fake_chat(message, session_id=None):
        return response(session_id or "generated")

    monkeypatch.setattr(api.service, "chat", fake_chat)
    with TestClient(api.app) as client:
        valid = client.post("/chat", json={"message": "How many incidents?"})
        empty = client.post("/chat", json={"message": "   "})
        oversized = client.post("/chat", json={"message": "x" * 2001})
        session = client.post("/chat", json={"message": "hello", "session_id": "safe_session"})
    assert valid.status_code == 200 and valid.json()["session_id"] == "generated"
    assert empty.status_code == 422
    assert oversized.status_code == 422
    assert session.json()["session_id"] == "safe_session"


def test_session_deletion(monkeypatch):
    deleted = []
    monkeypatch.setattr(api.service, "delete_session", lambda sid: deleted.append(sid) or sid == "known")
    with TestClient(api.app) as client:
        assert client.delete("/sessions/known").json() == {"deleted": True}
        assert client.delete("/sessions/missing").json() == {"deleted": False}
    assert deleted == ["known", "missing"]


def test_gemini_unavailable_fallback_is_still_success(monkeypatch):
    async def fake_chat(message, session_id=None):
        return response(ai_used=False)

    monkeypatch.setattr(api.service, "chat", fake_chat)
    with TestClient(api.app) as client:
        result = client.post("/chat", json={"message": "brief me"})
    assert result.status_code == 200 and result.json()["ai_used"] is False
