from layer_3_cis.router import route_entry


def run_layer3(layer2_output):
    if isinstance(layer2_output, list):
        detections = layer2_output
    elif isinstance(layer2_output, dict):
        detections = layer2_output.get("detections", []) or []
    else:
        detections = []

    results = []

    for entry in detections:
        detection = entry.get("detection", {}) or {}

        label = detection.get("label", "benign")
        confidence = detection.get("confidence", 0.0)

        # Skip CIS enrichment for benign / low-confidence logs
        if label == "benign" and confidence < 0.4:
            entry["cis_benchmark"] = {
                "status": "skipped_benign_event",
                "reason": "No significant threat detected"
            }
            results.append(entry)
            continue

        enriched_entry = route_entry(entry)
        results.append(enriched_entry)

    return results
