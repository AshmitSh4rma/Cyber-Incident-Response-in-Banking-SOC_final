"""Small, isolated async adapter around Google's Gemini SDK."""

from __future__ import annotations

import asyncio

from google import genai
from google.genai import errors, types

from prototype_ai_chat.config import GeminiSettings


class GeminiClientError(RuntimeError):
    """Base class for safe, categorized Gemini failures."""


class GeminiAuthenticationError(GeminiClientError):
    pass


class GeminiInvalidModelError(GeminiClientError):
    pass


class GeminiQuotaError(GeminiClientError):
    pass


class GeminiNetworkError(GeminiClientError):
    pass


class GeminiTimeoutError(GeminiClientError):
    pass


class GeminiEmptyResponseError(GeminiClientError):
    pass


class GeminiClient:
    """Generate text without logging credentials, prompts, or responses."""

    def __init__(self, settings: GeminiSettings) -> None:
        self._settings = settings
        self._client = genai.Client(
            api_key=settings.api_key,
            http_options=types.HttpOptions(
                timeout=int(settings.timeout_seconds * 1000),
            ),
        )

    async def generate(self, prompt: str) -> str:
        if not prompt.strip():
            raise ValueError("A non-empty prompt is required.")

        try:
            response = await asyncio.wait_for(
                self._client.aio.models.generate_content(
                    model=self._settings.model,
                    contents=prompt,
                ),
                timeout=self._settings.timeout_seconds + 2,
            )
        except asyncio.TimeoutError as exc:
            raise GeminiTimeoutError("Gemini request timed out.") from exc
        except errors.APIError as exc:
            code = getattr(exc, "code", None)
            if code in {401, 403}:
                raise GeminiAuthenticationError(
                    "Gemini authentication was rejected."
                ) from exc
            if code == 404:
                raise GeminiInvalidModelError(
                    "The configured Gemini model is unavailable."
                ) from exc
            if code == 429:
                raise GeminiQuotaError(
                    "Gemini quota or rate limit was reached."
                ) from exc
            if code == 408:
                raise GeminiTimeoutError("Gemini request timed out.") from exc
            if isinstance(code, int) and code >= 500:
                raise GeminiNetworkError(
                    "Gemini service is temporarily unavailable."
                ) from exc
            raise GeminiClientError("Gemini rejected the request.") from exc
        except (ConnectionError, OSError) as exc:
            raise GeminiNetworkError("Gemini network request failed.") from exc

        text = (response.text or "").strip()
        if not text:
            raise GeminiEmptyResponseError(
                "Gemini returned an empty or unusable response."
            )
        return text

    async def close(self) -> None:
        await self._client.aio.aclose()
