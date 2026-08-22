"""
CVSS 3.1 base-score conformance.

The README claimed "7 of 7 published reference vectors — exact" and there was no
test behind it. The implementation turned out to be right, but an unverifiable
claim in a pitch is a liability whether or not it happens to be true, so this
replaces it with something checkable and considerably stronger.

Two levels of check:

  1.  Nine real CVEs, using the vector string and base score NVD publishes for
      them. These are the concrete, quotable cases.

  2.  Every base-metric combination there is — 4 x 2 x 3 x 2 x 2 x 3 x 3 x 3 =
      2,592 vectors — against an independent implementation of the published
      equations. Nine vectors can pass by luck; 2,592 cannot. This is what
      actually rules out a wrong weight or a missed Scope adjustment, both of
      which are easy to get wrong and affect only part of the space.
"""

import itertools
import math

import pytest

from layer_5_cvss.engine_3_scoring.cvss_formula import calculate_base_score

# ─────────────────────────────────────────────────────────────────────────────
# Published reference vectors
#
# Vector strings and base scores as published by NVD (nvd@nist.gov as the
# scoring source), retrieved from the NVD CVE API. Chosen to span the metric
# space rather than to flatter: a Scope:Changed case, an AC:H case, an AV:L case,
# a PR:L case, and impact combinations from C:H/I:N/A:N through C:H/I:H/A:H.
#
# CVE-2020-1472 is NVD's own AV:L assessment of Zerologon, which scores 5.5 —
# lower than the vendor's. That disagreement is about metric *selection*, not
# arithmetic, and this test is about the arithmetic.
# ─────────────────────────────────────────────────────────────────────────────

NVD_REFERENCE_VECTORS = [
    ("CVE-2021-44228", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell
    ("CVE-2017-5638",  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # Struts / Equifax
    ("CVE-2019-0708",  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # BlueKeep
    ("CVE-2022-22965", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # Spring4Shell
    ("CVE-2021-26855", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),   # ProxyLogon
    ("CVE-2021-34527", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),   # PrintNightmare
    ("CVE-2018-11776", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),   # Struts OGNL
    ("CVE-2014-0160",  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),   # Heartbleed
    ("CVE-2020-1472",  "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),   # Zerologon (NVD)
]


def _parse(vector: str) -> dict[str, str]:
    """A CVSS base vector string into the metric dict the scorer expects."""
    return dict(part.split(":", 1) for part in vector.split("/"))


@pytest.mark.parametrize("cve,vector,expected", NVD_REFERENCE_VECTORS)
def test_published_reference_vectors_score_exactly(cve, vector, expected):
    assert calculate_base_score(_parse(vector)) == expected, cve


def test_the_reference_set_actually_spans_the_metric_space():
    """
    A reference set that only contains AV:N/AC:L/S:U vectors would pass while the
    other three quarters of the implementation was wrong.
    """
    seen: dict[str, set[str]] = {}
    for _cve, vector, _score in NVD_REFERENCE_VECTORS:
        for metric, value in _parse(vector).items():
            seen.setdefault(metric, set()).add(value)

    assert seen["S"] == {"U", "C"}, "must include a Scope:Changed case"
    assert seen["AC"] == {"L", "H"}, "must include a high-complexity case"
    assert {"N", "L"} <= seen["PR"], "must include a privileged case"
    assert {"N", "L"} <= seen["AV"], "must include a local-vector case"


# ─────────────────────────────────────────────────────────────────────────────
# Exhaustive conformance
# ─────────────────────────────────────────────────────────────────────────────

def _reference_base_score(m: dict[str, str]) -> float:
    """
    An independent implementation of the CVSS v3.1 base score equations,
    written from the specification (CVSS v3.1 Specification Document, section
    7.1) rather than from the module under test.

    Deliberately a separate transcription: the point is that two independent
    readings of the spec agree, which a self-comparison cannot show.
    """
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[m["AV"]]
    ac = {"L": 0.77, "H": 0.44}[m["AC"]]
    ui = {"N": 0.85, "R": 0.62}[m["UI"]]
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}
    scope_changed = m["S"] == "C"

    # Privileges Required is the one weight that depends on Scope.
    pr = ({"N": 0.85, "L": 0.68, "H": 0.50} if scope_changed
          else {"N": 0.85, "L": 0.62, "H": 0.27})[m["PR"]]

    iss = 1 - ((1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]]))
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    combined = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)

    # Roundup, per the specification's integer-arithmetic definition, which
    # exists precisely so floating point cannot shift a score by 0.1.
    scaled = round(combined * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000.0) + 1) / 10.0


ALL_METRICS = list(itertools.product(
    "NALP",     # AV
    "LH",       # AC
    "NLH",      # PR
    "NR",       # UI
    "UC",       # S
    "NLH",      # C
    "NLH",      # I
    "NLH",      # A
))


def test_the_whole_metric_space_is_covered():
    assert len(ALL_METRICS) == 2592


def test_every_possible_vector_matches_an_independent_implementation():
    """
    All 2,592 base-metric combinations. A wrong weight or a missed Scope
    adjustment shows up here even when it leaves the common vectors correct.
    """
    mismatches = []
    for av, ac, pr, ui, s, c, i, a in ALL_METRICS:
        metrics = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}
        ours = calculate_base_score(metrics)
        theirs = _reference_base_score(metrics)
        if ours != theirs:
            vector = "/".join(f"{k}:{v}" for k, v in metrics.items())
            mismatches.append(f"{vector}: got {ours}, expected {theirs}")

    assert not mismatches, (
        f"{len(mismatches)} of {len(ALL_METRICS)} vectors disagree; first five: "
        + "; ".join(mismatches[:5])
    )


def test_scores_stay_inside_the_defined_range():
    for av, ac, pr, ui, s, c, i, a in ALL_METRICS:
        score = calculate_base_score(
            {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}
        )
        assert 0.0 <= score <= 10.0
        # Every CVSS score is a single-decimal value; a raw float here would mean
        # the roundup was skipped.
        assert score == round(score, 1)


def test_no_impact_scores_zero_whatever_the_exploitability():
    """
    A vulnerability with no confidentiality, integrity or availability impact
    scores 0.0 regardless of how easy it is to reach — the spec short-circuits,
    and getting this wrong would inflate every harmless finding.
    """
    for av, ac, pr, ui, s in itertools.product("NALP", "LH", "NLH", "NR", "UC"):
        metrics = {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": "N", "I": "N", "A": "N"}
        assert calculate_base_score(metrics) == 0.0
