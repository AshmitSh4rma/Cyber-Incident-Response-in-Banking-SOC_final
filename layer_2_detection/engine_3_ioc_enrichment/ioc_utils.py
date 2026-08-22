from typing import Any


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def normalize_list(values: Any) -> list[str]:
    if values is None:
        return []

    if isinstance(values, list):
        return [normalize_text(v) for v in values if normalize_text(v)]

    value = normalize_text(values)
    return [value] if value else []


def deduplicate(values: list[str]) -> list[str]:
    seen = set()
    result = []

    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result
