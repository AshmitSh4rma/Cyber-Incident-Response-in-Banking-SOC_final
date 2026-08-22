from layer_5_cvss.cvss_schema import AIAnalysisInput, ExploitabilityMetrics
from layer_5_cvss.engine_1_metric_mapping.exploitability_mapper import (
    map_exploitability as core_map_exploitability,
)


def map_exploitability(ai_input: AIAnalysisInput) -> ExploitabilityMetrics:
    """
    Entry point for engine 1.
    """
    return core_map_exploitability(ai_input)
