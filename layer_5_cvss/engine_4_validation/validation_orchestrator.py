from layer_5_cvss.cvss_schema import ExploitabilityMetrics, ImpactMetrics
from layer_5_cvss.engine_4_validation.fallback_handler import apply_fallbacks


def validate_and_fallback(exploitability: dict, impact: dict) -> tuple[ExploitabilityMetrics, ImpactMetrics]:
    """
    Entry point for Engine 4.
    Ensures that any missing (None) values in the metrics are correctly filled
    using the defined system fallbacks, making it ready for scoring calculation.
    """
    return apply_fallbacks(exploitability, impact)
