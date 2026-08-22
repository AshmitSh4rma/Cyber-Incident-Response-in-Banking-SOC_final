from layer_5_cvss.cvss_schema import AIAnalysisInput, ImpactMetrics
from layer_5_cvss.engine_2_impact_mapping.impact_mapper import (
    map_impact as core_map_impact,
)


def map_impact(ai_input: AIAnalysisInput) -> ImpactMetrics:
    """
    Entry point for engine 2.
    """
    return core_map_impact(ai_input)
