import math


def official_cvss_roundup(input_val):
    """
    Official CVSS 3.1 Roundup function.
    To avoid floating point errors that cause scores to be off by 0.1,
    the standard recommends scaling by 100,000 before rounding.
    """
    int_input = round(input_val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000.0) + 1) / 10.0

def calculate_base_score(metrics):
    """
    Implements the CVSS v3.1 Base Score Equations.

    Expected 'metrics' dict keys:
    AV, AC, PR, UI, S, C, I, A (using standard CVSS codes)
    """

    # 1. Metric Weights (CVSS 3.1 Standard)
    WEIGHTS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "UI": {"N": 0.85, "R": 0.62},
        "CIA": {"N": 0.0, "L": 0.22, "H": 0.56}
    }

    # Privileges Required weight depends on Scope (S)
    if metrics["S"] == "U":  # Unchanged
        pr_weight = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
    else:                    # Changed
        pr_weight = {"N": 0.85, "L": 0.68, "H": 0.50}[metrics["PR"]]

    # 2. Calculate Impact Sub Score (ISC_Base)
    # ISC_Base = 1 - [(1 - ImpactConf) × (1 - ImpactInteg) × (1 - ImpactAvail)]
    c = WEIGHTS["CIA"][metrics["C"]]
    i = WEIGHTS["CIA"][metrics["I"]]
    a = WEIGHTS["CIA"][metrics["A"]]

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

    # 3. Calculate Impact
    if metrics["S"] == "U":
        impact = 6.42 * isc_base
    else:
        # Complex formula for Scope Changed
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)**15

    # 4. Calculate Exploitability
    av = WEIGHTS["AV"][metrics["AV"]]
    ac = WEIGHTS["AC"][metrics["AC"]]
    ui = WEIGHTS["UI"][metrics["UI"]]

    exploitability = 8.22 * av * ac * pr_weight * ui

    # 5. Final Base Score Calculation
    if impact <= 0:
        return 0.0

    if metrics["S"] == "U":
        base_score = official_cvss_roundup(min((impact + exploitability), 10.0))
    else:
        # Apply 1.08 factor for Scope Changed
        base_score = official_cvss_roundup(min(1.08 * (impact + exploitability), 10.0))

    return base_score
