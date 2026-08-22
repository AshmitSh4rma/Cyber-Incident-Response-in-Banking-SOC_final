import json
import os

from .ioc_utils import normalize_text

IOC_FEED_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "mappings",
    "ioc_feed.json"
)


def load_ioc_feed() -> list[dict]:
    if not os.path.exists(IOC_FEED_PATH):
        return []

    try:
        with open(IOC_FEED_PATH, encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def lookup_iocs(observables: dict) -> list[dict]:
    feed = load_ioc_feed()
    matches = []

    ip_set = set(observables.get("ips", []))
    domain_set = set(observables.get("domains", []))
    url_set = set(observables.get("urls", []))
    hash_set = set(observables.get("hashes", []))

    for entry in feed:
        observable = normalize_text(entry.get("observable"))
        obs_type = normalize_text(entry.get("type"))

        matched = False

        if obs_type == "ip" and observable in ip_set or obs_type == "domain" and observable in domain_set or obs_type == "url" and observable in url_set or obs_type == "hash" and observable in hash_set:
            matched = True

        if matched:
            matches.append({
                "observable": observable,
                "type": obs_type,
                "threat_type": entry.get("threat_type", "unknown"),
                "confidence": entry.get("confidence", 0.5),
                "source": entry.get("source", "local_ioc_feed")
            })

    return matches
