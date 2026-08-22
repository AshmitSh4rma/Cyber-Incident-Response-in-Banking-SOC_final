import json
import os

from layer_5_cvss.cvss_schema import ExploitabilityMetrics, ImpactMetrics


def load_json(filepath: str) -> dict:
    with open(filepath) as f:
        return json.load(f)

def apply_fallbacks(exploitability: dict, impact: dict) -> tuple[ExploitabilityMetrics, ImpactMetrics]:
    """
    Checks for None values in the metrics and populates them using defaults
    from the fallback map.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    metrics_path = os.path.join(base_dir, "mappings", "cvss_metric_map.json")
    full_map = load_json(metrics_path)

    fallbacks = full_map.get("engine_4_fallbacks", {})
    e_map = full_map["engine_1_exploitability"]
    i_map = full_map["engine_2_impact"]

    default_av = e_map["attack_vector"].get(fallbacks.get("attack_vector", "network"), "N")
    default_ac = e_map["attack_complexity"].get(fallbacks.get("attack_complexity", "low"), "L")
    default_pr = e_map["privileges_required"].get(fallbacks.get("privileges_required", "none"), "N")
    default_ui = e_map["user_interaction"].get(fallbacks.get("user_interaction", "none"), "N")

    default_c = i_map["confidentiality"].get(fallbacks.get("confidentiality", "high"), "H")
    default_i = i_map["integrity"].get(fallbacks.get("integrity", "high"), "H")
    default_a = i_map["availability"].get(fallbacks.get("availability", "high"), "H")
    default_s = i_map["scope"].get(fallbacks.get("scope", "unchanged"), "U")

    valid_exploitability: ExploitabilityMetrics = {
        "AV": exploitability.get("AV") if exploitability.get("AV") else default_av,
        "AC": exploitability.get("AC") if exploitability.get("AC") else default_ac,
        "PR": exploitability.get("PR") if exploitability.get("PR") else default_pr,
        "UI": exploitability.get("UI") if exploitability.get("UI") else default_ui
    }

    valid_impact: ImpactMetrics = {
        "C": impact.get("C") if impact.get("C") else default_c,
        "I": impact.get("I") if impact.get("I") else default_i,
        "A": impact.get("A") if impact.get("A") else default_a,
        "S": impact.get("S") if impact.get("S") else default_s
    }

    return valid_exploitability, valid_impact
