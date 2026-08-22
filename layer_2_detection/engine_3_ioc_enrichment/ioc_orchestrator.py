from .ioc_lookup import lookup_iocs
from .observable_extractor import extract_observables
from .reputation_mapper import map_reputation


def run_ioc_enrichment(event: dict) -> dict:
    observables = extract_observables(event)
    matches = lookup_iocs(observables)
    reputation = map_reputation(matches)

    event["ioc_enrichment"] = {
        "observables": observables,
        "matched": reputation.get("matched", False),
        "risk_level": reputation.get("risk_level", "low"),
        "match_count": reputation.get("match_count", 0),
        "matched_iocs": reputation.get("matched_iocs", [])
    }

    return event
