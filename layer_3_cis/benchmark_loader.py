import json
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CATALOG_DIR = BASE_DIR / "mappings" / "benchmark_catalog"


CATALOG_FILES = {
    "web": CATALOG_DIR / "web_owasp_catalog.json",
    "network": CATALOG_DIR / "network_controls_catalog.json",
}


@lru_cache(maxsize=len(CATALOG_FILES) + 1)
def load_catalog(domain: str) -> list[dict]:
    """
    Load the benchmark catalogue for a domain.

    Cached because this is called once per event and the network catalogue is a
    megabyte of JSON. Re-parsing it for every record made control mapping the
    slowest layer in the pipeline by an order of magnitude, for no reason: the
    catalogues are read-only reference data that never change during a run.

    Callers must not mutate the returned list — they all share it.
    """
    domain = domain.strip().lower()
    if domain not in CATALOG_FILES:
        return []

    file_path = CATALOG_FILES[domain]

    if not file_path.exists():
        return []

    with file_path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data

    return []
