from layer_5_cvss.cvss_schema import (
    ExploitabilityMetrics,
    ImpactMetrics,
    ScoringResults,
)
from layer_5_cvss.engine_3_scoring.cvss_formula import calculate_base_score
from layer_5_cvss.engine_3_scoring.severity_mapper import get_severity


def generate_vector_string(exploitability: ExploitabilityMetrics, impact: ImpactMetrics) -> str:
    """
    Constructs the CVSS v3.1 vector string.
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
    """
    vector_parts = [
        "CVSS:3.1",
        f"AV:{exploitability.get('AV', 'N')}",
        f"AC:{exploitability.get('AC', 'L')}",
        f"PR:{exploitability.get('PR', 'N')}",
        f"UI:{exploitability.get('UI', 'N')}",
        f"S:{impact.get('S', 'U')}",
        f"C:{impact.get('C', 'N')}",
        f"I:{impact.get('I', 'N')}",
        f"A:{impact.get('A', 'N')}"
    ]
    return "/".join(vector_parts)

def generate_score_and_vector(exploitability: ExploitabilityMetrics, impact: ImpactMetrics) -> ScoringResults:
    """
    Calculates Base Score and creates Vector String.
    Assumes metrics are fully populated (no None values).
    """
    metrics_combined = {**exploitability, **impact}

    # Calculate score using formula
    base_score = calculate_base_score(metrics_combined)

    # Generate vector string
    vector_string = generate_vector_string(exploitability, impact)

    # Get severity
    severity = get_severity(base_score)

    return {
        "vector_string": vector_string,
        "base_score": base_score,
        "severity": severity
    }
