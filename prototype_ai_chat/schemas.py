"""Request and response contracts for the standalone chatbot prototype."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


MAX_REQUEST_LENGTH = 2000


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_REQUEST_LENGTH)
    session_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")

    @field_validator("message")
    @classmethod
    def message_must_contain_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("message must not be blank")
        return cleaned


class EvidenceItem(BaseModel):
    type: str
    id: str


class ChatResponse(BaseModel):
    answer: str
    intent: str
    evidence: list[EvidenceItem]
    records_considered: int
    context_truncated: bool
    ai_used: bool
    model: str | None
    session_id: str
    count: int | None = None
    filters: dict[str, str] | None = None
    grounding_status: str | None = None


class HealthResponse(BaseModel):
    status: str
    database: str
    gemini: str
    model: str | None
