"""
Run the whole pipeline offline and write every artifact the dashboard reads.

Useful for two things: seeding a demo without starting a server, and seeing the
per-layer timing breakdown on real data.

    python dev_run.py                      # the multi-stage attack scenario
    python dev_run.py path/to/logs.json    # any JSON or JSONL log file
"""

import json
import logging
import sys
import time
from pathlib import Path

from layer_1_feature_engineering.ingestion_orchestrator import (
    process_json_text,
    process_jsonl_text,
)
from pipeline import run_full_pipeline
from soc_metrics import compute_metrics

logging.basicConfig(level=logging.WARNING)

BASE_DIR = Path(__file__).resolve().parent

# The flagship demo input: a coherent banking intrusion plus benign traffic and a
# scheduled scan, so campaign correlation has something real to reconstruct.
DEFAULT_INPUT = BASE_DIR / "demo_attack_scenario.json"


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _parse(content: str) -> list[dict]:
    try:
        return process_json_text(content)
    except ValueError:
        return process_jsonl_text(content)


def main() -> int:
    input_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    if not input_file.exists():
        print(f"Input file not found: {input_file}")
        return 1

    # Schema first: Layer 2 reads the analyst suppression list during detection,
    # so the tables must exist before the pipeline runs, not after it.
    from db_manager import init_db
    init_db()

    print(f"Reading {input_file.name} ...")
    records = _parse(input_file.read_text(encoding="utf-8"))
    print(f"  {len(records)} log records")

    print("Running pipeline (L1 -> L2 -> L2.5 -> L3 -> L4 -> L5 -> L6) ...")
    started = time.perf_counter()
    output = run_full_pipeline(records)
    elapsed = time.perf_counter() - started

    events = output["events"]
    campaigns = output["campaigns"]

    # Persist. The database is the source of truth the API serves from; the JSON
    # copies are the static fallback the dashboard can read with no backend.
    from db_manager import save_incident, replace_campaigns

    for event in events:
        save_incident(event)
    replace_campaigns(campaigns)

    _write_json(BASE_DIR / "frontend_output.json", output)
    _write_json(BASE_DIR / "Frontend" / "public" / "frontend_output.json", output)

    metrics = compute_metrics(events, campaigns, feedback=[], pipeline_seconds=elapsed)
    _write_json(BASE_DIR / "Frontend" / "public" / "soc_metrics.json", metrics)

    # ── Report ───────────────────────────────────────────────────────────────
    from collections import Counter

    labels = Counter(e["detection"].get("label") for e in events)
    sevs = Counter(e["detection"].get("severity") for e in events)

    print()
    print(f"Completed in {elapsed:.3f}s")
    print(f"  verdicts   : {dict(labels)}")
    print(f"  severities : {dict(sevs)}")
    print()
    print(f"Campaign correlation found {len(campaigns)} campaign(s):")
    for c in campaigns:
        chain = " -> ".join(s["stage"] for s in c["kill_chain"])
        print(f"  {c['campaign_id']}  [{c['severity']:8s}] {c['incident_count']:2d} alerts  "
              f"{c['progression_pct']:3d}% progression")
        print(f"           {c['name']}")
        print(f"           {chain}")
    print()
    con = metrics["consolidation"]
    print(f"Consolidation: {con['headline']}")
    print(f"Analyst time saved (modelled): {metrics['time']['hours_saved']}h")
    print()
    print("Per-layer timing (seconds):")
    for stage, secs in output["timing"].items():
        print(f"  {stage:22s} {secs}")
    print()
    print("Wrote frontend_output.json, Frontend/public/frontend_output.json,")
    print("      Frontend/public/soc_metrics.json, soc_incidents.db")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
