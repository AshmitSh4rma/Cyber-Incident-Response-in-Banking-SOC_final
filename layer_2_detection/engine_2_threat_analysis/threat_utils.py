from typing import Any


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ["true", "1", "yes"]
    return False


def append_reason(reasons: list, reason: str):
    if reason and reason not in reasons:
        reasons.append(reason)
    return reasons
