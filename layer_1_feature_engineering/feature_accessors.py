from typing import Any

SEARCH_CONTAINERS = [
    "normalized_core",
    "structured_payload",
    "parsed_fields",
    "raw_event",
    "additional_fields",
]


def _get_from_container(container: Any, key: str) -> Any:
    if isinstance(container, dict) and key in container:
        return container[key]
    return None


def get_field(event: dict[str, Any], *keys: str, default=None):
    """
    Search for a field in this order:
    1. top-level event
    2. normalized_core
    3. structured_payload
    4. parsed_fields
    5. raw_event
    6. additional_fields
    """
    for key in keys:
        if key in event and event[key] is not None:
            return event[key]

        for container_name in SEARCH_CONTAINERS:
            container = event.get(container_name)
            value = _get_from_container(container, key)
            if value is not None:
                return value

    return default


def has_field(event: dict[str, Any], *keys: str) -> bool:
    value = get_field(event, *keys, default=None)
    return value is not None


def get_str(event: dict[str, Any], *keys: str, default=None) -> str | None:
    value = get_field(event, *keys, default=default)
    if value is None:
        return default
    return str(value)


def get_int(event: dict[str, Any], *keys: str, default=None):
    value = get_field(event, *keys, default=default)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_float(event: dict[str, Any], *keys: str, default=None):
    value = get_field(event, *keys, default=default)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def get_list(event: dict[str, Any], *keys: str, default=None) -> list[Any]:
    value = get_field(event, *keys, default=default)
    if value is None:
        return [] if default is None else default
    if isinstance(value, list):
        return value
    return [value]


def get_dict(event: dict[str, Any], *keys: str, default=None) -> dict[str, Any]:
    value = get_field(event, *keys, default=default)
    if isinstance(value, dict):
        return value
    return {} if default is None else default
