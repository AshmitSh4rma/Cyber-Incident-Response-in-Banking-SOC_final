import csv
import io
import json
from typing import Any

from layer_1_feature_engineering.ingestion_normalizer import normalize_record

# ─────────────────────────────────────────
# JSON Parsing
# ─────────────────────────────────────────

def parse_json_content(content: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    if isinstance(parsed, dict):
        return [parsed]

    if isinstance(parsed, list):
        if not all(isinstance(item, dict) for item in parsed):
            raise ValueError("JSON array must contain only JSON objects")
        return parsed

    raise ValueError("JSON must be an object or an array of objects")


def parse_jsonl_content(content: str) -> list[dict[str, Any]]:
    records = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSONL at line {line_num}: {e}") from e

        if not isinstance(obj, dict):
            raise ValueError(f"JSONL line {line_num} must be a JSON object")

        records.append(obj)

    return records


# ─────────────────────────────────────────
# CSV Parsing
# ─────────────────────────────────────────

def parse_csv_content(content: str) -> list[dict[str, Any]]:
    try:
        buffer = io.StringIO(content)
        reader = csv.DictReader(buffer)

        if not reader.fieldnames:
            raise ValueError("CSV file has no header row")

        records = []
        for row in reader:
            cleaned_row = {}
            for key, value in row.items():
                if key is None:
                    continue
                cleaned_key = str(key).strip()
                cleaned_value = value.strip() if isinstance(value, str) else value
                cleaned_row[cleaned_key] = cleaned_value

            # skip completely empty rows
            if any(v not in (None, "") for v in cleaned_row.values()):
                records.append(cleaned_row)

        if not records:
            raise ValueError("CSV file contains no data rows")

        return records

    except csv.Error as e:
        raise ValueError(f"Invalid CSV: {e}") from e


# ─────────────────────────────────────────
# Processing Pipeline
# ─────────────────────────────────────────

def process_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_records = []
    for record in records:
        normalized = normalize_record(record)
        normalized_records.append(normalized)
    return normalized_records


def process_json_text(content: str) -> list[dict[str, Any]]:
    records = parse_json_content(content)
    return process_records(records)


def process_jsonl_text(content: str) -> list[dict[str, Any]]:
    records = parse_jsonl_content(content)
    return process_records(records)


def process_csv_text(content: str) -> list[dict[str, Any]]:
    records = parse_csv_content(content)
    return process_records(records)
