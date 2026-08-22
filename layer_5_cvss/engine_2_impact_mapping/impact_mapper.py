import json
import os

from layer_5_cvss.cvss_schema import AIAnalysisInput, ImpactMetrics


def load_json(filepath: str) -> dict:
    with open(filepath) as f:
        return json.load(f)

def get_mapping_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    metrics_path = os.path.join(base_dir, "mappings", "cvss_metric_map.json")
    rules_path = os.path.join(base_dir, "mappings", "constraint_rules.json")
    return load_json(metrics_path), load_json(rules_path)

def apply_impact_constraints(ai_input: AIAnalysisInput, current_metrics: dict, rules: dict):
    # 1. Check intent-based rules
    intent = ai_input.get("intent")
    if intent and intent in rules.get("intents", {}):
        intent_rules = rules["intents"][intent].get("impact", {})
        for key, val in intent_rules.items():
            if key in current_metrics:
                current_metrics[key] = val

    # 2. Check asset criticality based rules
    criticality = ai_input.get("asset_criticality")
    if criticality and criticality in rules.get("asset_criticality", {}):
        crit_rules = rules["asset_criticality"][criticality].get("impact", {})
        for key, val in crit_rules.items():
            if key in current_metrics:
                current_metrics[key] = val

    return current_metrics

def map_impact(ai_input: AIAnalysisInput) -> ImpactMetrics:
    impact_data = ai_input.get("impact", {})

    input_metrics = {
        "confidentiality": impact_data.get("confidentiality"),
        "integrity": impact_data.get("integrity"),
        "availability": impact_data.get("availability"),
        "scope": ai_input.get("scope")
    }

    metrics_map, rules = get_mapping_data()

    constrained_metrics = apply_impact_constraints(ai_input, input_metrics, rules)

    c_map = metrics_map["engine_2_impact"]["confidentiality"]
    i_map = metrics_map["engine_2_impact"]["integrity"]
    a_map = metrics_map["engine_2_impact"]["availability"]
    s_map = metrics_map["engine_2_impact"]["scope"]

    return {
        "C": c_map.get(str(constrained_metrics["confidentiality"]).lower(), None) if constrained_metrics["confidentiality"] else None,
        "I": i_map.get(str(constrained_metrics["integrity"]).lower(), None) if constrained_metrics["integrity"] else None,
        "A": a_map.get(str(constrained_metrics["availability"]).lower(), None) if constrained_metrics["availability"] else None,
        "S": s_map.get(str(constrained_metrics["scope"]).lower(), None) if constrained_metrics["scope"] else None
    }
