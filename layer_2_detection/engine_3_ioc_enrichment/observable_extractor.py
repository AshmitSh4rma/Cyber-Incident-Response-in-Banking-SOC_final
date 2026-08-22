from .ioc_utils import deduplicate, normalize_text


def extract_observables(event: dict) -> dict:
    raw_event = event.get("raw_event", {}) or {}

    ips = [
        normalize_text(event.get("source_ip")),
        normalize_text(event.get("source", {}).get("ip")),
        normalize_text(event.get("IpAddress")),
        normalize_text(event.get("ClientIP")),
    ]


    domains = [
        normalize_text(event.get("domain")),
        normalize_text(raw_event.get("domain")),
        normalize_text(raw_event.get("host")),
    ]

    urls = [
        normalize_text(event.get("url")),
        normalize_text(raw_event.get("url")),
    ]

    hashes = [
        normalize_text(event.get("file_hash")),
        normalize_text(raw_event.get("file_hash")),
        normalize_text(raw_event.get("hash")),
    ]

    return {
        "ips": deduplicate([x for x in ips if x]),
        "domains": deduplicate([x for x in domains if x]),
        "urls": deduplicate([x for x in urls if x]),
        "hashes": deduplicate([x for x in hashes if x]),
    }
