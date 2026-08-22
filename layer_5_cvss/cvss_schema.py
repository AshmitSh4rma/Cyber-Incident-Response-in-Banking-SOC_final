from typing import Literal, TypedDict

# Type aliases for valid CVSS metric values
AttackVector = Literal["network", "adjacent", "local", "physical", "N", "A", "L", "P"]
AttackComplexity = Literal["low", "high", "L", "H"]
PrivilegesRequired = Literal["none", "low", "high", "N", "L", "H"]
UserInteraction = Literal["none", "required", "N", "R"]
ImpactMetric = Literal["high", "low", "none", "H", "L", "N"]
ScopeMetric = Literal["unchanged", "changed", "U", "C"]

class AIImpact(TypedDict, total=False):
    confidentiality: ImpactMetric | None
    integrity: ImpactMetric | None
    availability: ImpactMetric | None

class AIAnalysisInput(TypedDict, total=False):
    intent: str | None
    attack_vector: AttackVector | None
    attack_complexity: AttackComplexity | None
    privileges_required: PrivilegesRequired | None
    user_interaction: UserInteraction | None
    scope: ScopeMetric | None
    impact: AIImpact | None
    asset_criticality: Literal["low", "medium", "high", "critical"] | None

class ExploitabilityMetrics(TypedDict):
    AV: str
    AC: str
    PR: str
    UI: str

class ImpactMetrics(TypedDict):
    C: str
    I: str  # noqa: E741 — CVSS metric key; renaming breaks the vector string
    A: str
    S: str

class ScoringResults(TypedDict):
    vector_string: str
    base_score: float
    severity: str

class FinalCVSSOutput(TypedDict):
    cvss: dict[str, any]
