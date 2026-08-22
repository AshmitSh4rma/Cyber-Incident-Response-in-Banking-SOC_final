import math
import re
from functools import lru_cache
from typing import Any

from layer_3_cis.benchmark_loader import load_catalog


@lru_cache(maxsize=8)
def _keyword_weights(domain: str) -> dict[str, float]:
    """
    What a keyword match is worth, by how rare that keyword is in the catalogue.

    Without this every term scored the same, and the CIS network catalogue is
    413 Cisco controls where words like "management", "console" and "configured"
    appear in hundreds of titles. A query for a Telnet-exposed camera would score
    "Create Periodic Backups of Firepower Management Center" above
    "Ensure 'Telnet' is disabled", because the three generic words outvoted the
    one that mattered.

    Standard inverse document frequency fixes it: a keyword in 4 of 413 entries
    is worth far more than one in 200. Clamped at both ends so a common word
    still counts for something and a one-off cannot win on its own.
    """
    catalog = load_catalog(domain)
    total = len(catalog)
    if not total:
        return {}

    frequency: dict[str, int] = {}
    for entry in catalog:
        for keyword in set(_normalize_list(entry.get("keywords", []))):
            frequency[keyword] = frequency.get(keyword, 0) + 1

    return {
        keyword: max(0.5, min(3.0, math.log(total / (1 + count))))
        for keyword, count in frequency.items()
    }


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalize_list(values: Any) -> list[str]:
    if not values:
        return []
    if isinstance(values, list):
        return [_normalize_text(v) for v in values if _normalize_text(v)]
    return [_normalize_text(values)]


@lru_cache(maxsize=8)
def _normalised_catalog(domain: str) -> tuple[tuple[dict, dict], ...]:
    """
    The catalogue with its searchable text lowercased once.

    Scoring used to normalise every entry's tags, keywords, section, title and
    description on every comparison — 4.4 million string operations to map 25
    events, because the same 413 controls were re-lowercased for each one. The
    catalogue is read-only reference data, so this is done once per process.

    Returns (entry, normalised) pairs so the caller still has the original entry
    to build its result from. Tags and keywords become sets: membership is all the
    scorer asks of them, and it asks a lot.
    """
    prepared = []
    for entry in load_catalog(domain):
        prepared.append((entry, {
            "tags": frozenset(_normalize_list(entry.get("tags", []))),
            "keywords": frozenset(_normalize_list(entry.get("keywords", []))),
            "section": _normalize_text(entry.get("section", "")),
            "title": _normalize_text(entry.get("title", "")),
            "description": _normalize_text(entry.get("description", "")),
        }))
    return tuple(prepared)


def _score_entry(
    normalised: dict,
    query_tags: list[str],
    query_keywords: list[str],
    section_hint: list[str],
    weights: dict[str, float],
) -> float:
    score = 0.0

    entry_tags = normalised["tags"]
    entry_keywords = normalised["keywords"]
    entry_section = normalised["section"]
    entry_title = normalised["title"]
    entry_description = normalised["description"]

    # Tags are curated and low-cardinality, so they keep a flat weight.
    for tag in query_tags:
        if tag in entry_tags:
            score += 3.0

    for keyword in query_keywords:
        # A term absent from the catalogue's keyword index still gets the floor
        # weight, so title-only matches are not discarded.
        weight = weights.get(keyword, 1.0)
        if keyword in entry_keywords:
            score += weight
        elif keyword in entry_title:
            score += weight * 0.7
        elif keyword in entry_description:
            score += weight * 0.3

    for hint in section_hint:
        if hint and hint in entry_section:
            score += 2.0

    return score


def _normalize_title_for_family(title: str) -> str:
    title = _normalize_text(title)
    title = title.replace("'", "")
    title = title.replace('"', "")
    title = re.sub(r"\s+", " ", title)
    return title


def retrieve_benchmarks(
    domain: str,
    query_tags: list[str] | None = None,
    query_keywords: list[str] | None = None,
    section_hint: list[str] | None = None,
    max_results: int = 5
) -> list[dict]:
    """
    Retrieves the most relevant benchmark/control entries from the domain catalog.
    Collapses similar entries so AI gets one representative benchmark per control family.
    """
    query_tags = _normalize_list(query_tags or [])
    query_keywords = _normalize_list(query_keywords or [])
    section_hint = _normalize_list(section_hint or [])

    catalog = _normalised_catalog(domain)
    if not catalog:
        return []

    weights = _keyword_weights(domain)

    scored = []
    for entry, normalised in catalog:
        score = _score_entry(normalised, query_tags, query_keywords, section_hint, weights)
        if score > 0:
            scored.append((score, entry))

    if not scored:
        import logging
        logging.warning(
            f"[CIS] No matches for domain='{domain}' tags={query_tags} keywords={query_keywords}"
        )
        return []

    scored.sort(key=lambda x: x[0], reverse=True)

    family_best = {}

    for score, entry in scored:
        family_key = _normalize_title_for_family(entry.get("title", ""))

        if not family_key:
            family_key = (
                str(entry.get("benchmark_id", "")),
                str(entry.get("source_benchmark", "")),
            )

        if family_key not in family_best:
            family_best[family_key] = {
                "score": score,
                "entry": entry,
                "source_benchmarks_considered": set(
                    [entry.get("source_benchmark")] if entry.get("source_benchmark") else []
                )
            }
        else:
            family_best[family_key]["source_benchmarks_considered"].update(
                [entry.get("source_benchmark")] if entry.get("source_benchmark") else []
            )

    collapsed = sorted(
        family_best.values(),
        key=lambda item: item["score"],
        reverse=True
    )

    results = []
    for item in collapsed[:max_results]:
        entry = item["entry"]
        results.append({
            "benchmark_id": entry.get("benchmark_id"),
            "source_benchmark": entry.get("source_benchmark"),
            "source_benchmarks_considered": sorted(item["source_benchmarks_considered"]),
            "framework": entry.get("framework"),
            "title": entry.get("title"),
            "section": entry.get("section"),
            "profile_level": entry.get("profile_level"),
            "description": entry.get("description"),
            "rationale": entry.get("rationale"),
            "audit_procedure": entry.get("audit_procedure"),
            "remediation": entry.get("remediation"),
            "references": entry.get("references"),
            "tags": entry.get("tags", []),
            "keywords": entry.get("keywords", []),
        })

    return results
