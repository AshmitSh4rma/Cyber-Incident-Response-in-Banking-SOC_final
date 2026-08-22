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


def append_unique(items: list[str], value: str) -> list[str]:
    if value and value not in items:
        items.append(value)
    return items
