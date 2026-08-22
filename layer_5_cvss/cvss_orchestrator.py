import logging

from layer_5_cvss.cvss_fusion import fuse_final_response
from layer_5_cvss.engine_1_metric_mapping.metric_mapping_orchestrator import (
    map_exploitability,
)
from layer_5_cvss.engine_2_impact_mapping.impact_mapping_orchestrator import map_impact
from layer_5_cvss.engine_3_scoring.scoring_orchestrator import generate_score_and_vector
from layer_5_cvss.engine_4_validation.validation_orchestrator import (
    validate_and_fallback,
)

# Configure lightweight logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def run_cvss(ai_analysis: dict) -> dict:
    """
    Orchestrates the conversion of AI threat context into a
    standardized numerical risk score.
    """
    if not ai_analysis or not isinstance(ai_analysis, dict) or \
       (ai_analysis.get("intent") == "Suspicious Activity" and ai_analysis.get("attack_vector") == "unknown"):
        return {
            "vector": {},
            "vector_string": "N/A",
            "base_score": 0.0,
            "severity": "unknown"
        }

    # 🔹 ENGINE 1: Metric Mapping (Exploitability)
    exploitability_metrics = map_exploitability(ai_analysis)

    # 🔹 ENGINE 2: Impact Mapping (CIA + Scope)
    impact_metrics = map_impact(ai_analysis)

    # 🔹 ENGINE 4: Validation (Sanity Check & Fallbacks)
    # Validate and fill fallbacks before scoring so math formulas work
    valid_exploitability, valid_impact = validate_and_fallback(exploitability_metrics, impact_metrics)

    # 🔹 ENGINE 3: Scoring (Math & Severity)
    scoring_results = generate_score_and_vector(valid_exploitability, valid_impact)

    # 🔹 CVSS FUSION: Final block building
    final_cvss_block = fuse_final_response(valid_exploitability, valid_impact, scoring_results)

    return final_cvss_block
