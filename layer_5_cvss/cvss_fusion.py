from layer_5_cvss.cvss_schema import (
    ExploitabilityMetrics,
    FinalCVSSOutput,
    ImpactMetrics,
    ScoringResults,
)


def fuse_final_response(
    exploitability: ExploitabilityMetrics,
    impact: ImpactMetrics,
    scoring: ScoringResults
) -> FinalCVSSOutput:
    """
    Constructs the final CVSS JSON block for the next layers.
    """
    vector_string = scoring["vector_string"].replace("CVSS:3.1/", "")

    return {
        "vector": {
            **exploitability,
            **impact
        },
        "vector_string": vector_string,
        "base_score": scoring["base_score"],
        "severity": scoring["severity"]
    }
