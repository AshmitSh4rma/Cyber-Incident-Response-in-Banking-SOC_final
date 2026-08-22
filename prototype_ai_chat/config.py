"""Backend-only configuration for the Gemini connectivity prototype."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


class GeminiConfigurationError(RuntimeError):
    """Raised when required Gemini configuration is unavailable."""


@dataclass(frozen=True)
class GeminiSettings:
    api_key: str = field(repr=False)
    model: str
    timeout_seconds: float = 30.0


def load_gemini_settings() -> GeminiSettings:
    """Load local configuration without exposing the API key."""
    load_dotenv(REPOSITORY_ROOT / ".env", override=False)

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise GeminiConfigurationError(
            "GEMINI_API_KEY is not configured.\n"
            "Add it to the repository .env and retry."
        )

    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip()
    if not model:
        model = DEFAULT_GEMINI_MODEL

    return GeminiSettings(api_key=api_key, model=model)
