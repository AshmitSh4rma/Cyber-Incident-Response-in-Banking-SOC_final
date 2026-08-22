# json_parser.py
# Clean version for structured SOC-style LLM output

import json
import re

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _try_direct_parse(text: str):
    """Attempt 1: Direct JSON parse"""
    try:
        return json.loads(text.strip())
    except Exception:
        return None


def _try_extract_json_block(text: str):
    """Attempt 2: Extract JSON block between { }"""
    try:
        start = text.find("{")
        end = text.rfind("}")

        if start == -1 or end == -1 or start >= end:
            return None

        return json.loads(text[start:end + 1])
    except Exception:
        return None


def _try_clean_and_parse(text: str):
    """Attempt 3: Clean formatting issues then parse"""
    try:
        cleaned = text.strip()

        # Remove markdown fences
        cleaned = re.sub(r"```json\s*", "", cleaned)
        cleaned = re.sub(r"```\s*", "", cleaned)

        # Remove trailing commas
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)

        # Replace single quotes (careful usage)
        cleaned = re.sub(r"(?<![\\])'", '"', cleaned)

        return json.loads(cleaned)
    except Exception:
        return None


def _try_extract_after_clean(text: str):
    """Attempt 4: Clean + extract JSON"""
    try:
        cleaned = text.strip()
        cleaned = re.sub(r"```json\s*", "", cleaned)
        cleaned = re.sub(r"```\s*", "", cleaned)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)

        start = cleaned.find("{")
        end = cleaned.rfind("}")

        if start == -1 or end == -1 or start >= end:
            return None

        return json.loads(cleaned[start:end + 1])
    except Exception:
        return None


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def parse_llm_response(text: str, expected_keys: list = None) -> dict:
    """
    Parses LLM output into structured JSON.

    NO normalization.
    Returns raw parsed model output.

    Returns:
        {
            "parsed": bool,
            "data": dict | None,
            "raw_text": str,
            "parse_strategy": str,
            "missing_keys": list,
            "error": str | None
        }
    """

    if not text or not text.strip():
        return {
            "parsed": False,
            "data": None,
            "raw_text": text or "",
            "parse_strategy": "none",
            "missing_keys": expected_keys or [],
            "error": "Empty response from LLM"
        }

    strategies = [
        ("direct", _try_direct_parse),
        ("extract_block", _try_extract_json_block),
        ("clean_and_parse", _try_clean_and_parse),
        ("extract_after_clean", _try_extract_after_clean)
    ]

    for name, fn in strategies:
        result = fn(text)

        if isinstance(result, dict):
            # Optional validation (for debugging)
            missing = []
            if expected_keys:
                missing = [k for k in expected_keys if k not in result]

            return {
                "parsed": True,
                "data": result,   # 🔥 RAW model output (no mapping)
                "raw_text": text,
                "parse_strategy": name,
                "missing_keys": missing,
                "error": None
            }

    return {
        "parsed": False,
        "data": None,
        "raw_text": text,
        "parse_strategy": "failed",
        "missing_keys": expected_keys or [],
        "error": "All parse strategies failed"
    }


# ─────────────────────────────────────────
# SAFE ACCESSOR
# ─────────────────────────────────────────

def safe_get(parsed_result: dict, key: str, fallback=None):
    """
    Safely retrieves a key from parsed output.
    """
    if not parsed_result.get("parsed"):
        return fallback

    return parsed_result.get("data", {}).get(key, fallback)
