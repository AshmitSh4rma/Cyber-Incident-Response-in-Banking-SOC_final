"""Harmless live connectivity check for the isolated Gemini adapter."""

from __future__ import annotations

import asyncio

from prototype_ai_chat.config import (
    GeminiConfigurationError,
    load_gemini_settings,
)
from prototype_ai_chat.gemini_client import GeminiClient, GeminiClientError

EXPECTED_MARKER = "SENTRA_GEMINI_OK"
TEST_PROMPT = """You are participating in a connectivity test.

Respond with exactly:

SENTRA_GEMINI_OK
"""


async def run_smoke_test() -> int:
    try:
        settings = load_gemini_settings()
    except GeminiConfigurationError as exc:
        print(str(exc))
        return 2

    print("Gemini configuration: PASS")
    client = GeminiClient(settings)
    try:
        response = await client.generate(TEST_PROMPT)
    except GeminiClientError as exc:
        print(f"Gemini request: FAIL ({type(exc).__name__})")
        return 1
    finally:
        await client.close()

    print("Gemini authentication: PASS")
    print("Gemini request: PASS")
    if EXPECTED_MARKER not in response:
        print("Gemini response validation: FAIL")
        return 1

    print("Gemini response validation: PASS")
    print(f"Model: {settings.model}")
    print("\nSENTRA Gemini connectivity test PASSED.")
    return 0


def main() -> int:
    return asyncio.run(run_smoke_test())


if __name__ == "__main__":
    raise SystemExit(main())
