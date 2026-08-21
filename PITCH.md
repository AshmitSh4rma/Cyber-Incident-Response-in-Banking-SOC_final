# SENTRA — Pitch Notes

**Automated incident response for banking Security Operations Centers.**

Raw security telemetry in; a scored, control-mapped, playbook-ready incident out —
with the CIS control it violated and a defensible CVSS 3.1 score attached.
Six analysis layers, roughly one second, no analyst keystrokes.

---

## The one-line thesis

> Attackers break out of the first host in **29 minutes**. EU DORA gives a bank
> **4 hours** to file its initial notification. Meanwhile **46%** of the alerts in
> the analyst's queue are false positives.
>
> The bottleneck is not detection. It is *determination* — and every regulatory
> clock in banking starts the moment determination happens.

---

## The problem, in numbers

| Figure | Claim | Source |
| ------ | ----- | ------ |
| **$6.3M** | Average breach cost in financial services — highest of any sector (global average $4.99M) | IBM Cost of a Data Breach Report 2026 |
| **≈$2M** | Saved per breach by organisations using AI + automation in security operations; 1 in 4 still have not adopted them | IBM Cost of a Data Breach Report 2026 |
| **29 min** | Average eCrime breakout time; fastest observed 27 seconds | CrowdStrike 2026 Global Threat Report *(vendor telemetry)* |
| **73%** | Of security teams rank false positives their #1 detection challenge; "very frequent" FPs rose 13% → 20% YoY | SANS Detection & Response Survey 2025 |
| **46%** | Of all SOC alerts are false positives | Microsoft / Omdia State of the SOC 2026 |
| **1 in 4** | Malicious breaches are now AI-enabled (+56% YoY), costing ~$6M each | IBM Cost of a Data Breach Report 2026 |

---

## Why banking, specifically: the notification clocks

Speed is a legal requirement here, not a preference. A missed deadline is a
compliance breach independent of what the attacker did.

| Regime | Clock | Obligation |
| ------ | ----- | ---------- |
| **EU — DORA** | **4 hours** | Initial notification within 4h of classifying an ICT incident as major (≤24h from awareness); intermediate at 72h; final within 1 month. Applicable since 17 Jan 2025. |
| **India — CERT-In** | **6 hours** | Mandatory reporting within 6h of noticing an incident, including probing of critical networks. Directions of 28 Apr 2022 under s.70B, IT Act 2000. |
| **US — OCC / Fed / FDIC** | **36 hours** | Notify primary federal regulator ≤36h after determining a notification incident occurred. Compliance date 1 May 2022. |
| **US — SEC Item 1.05** | **4 business days** | Disclose a material incident on Form 8-K within 4 business days of determining materiality. Adopted 26 Jul 2023. |

Every clock starts at a *determination* — "classified as major", "determined to be
material", "noticed". Determination is triage. Triage is what SENTRA compresses.

---

## What it does — the six layers

| Layer | Function | Output |
| ----- | -------- | ------ |
| **L1** | Feature engineering — normalise, classify log family, extract temporal / behavioural / statistical / network / web / IoT / identity features | normalised event + 7 feature blocks |
| **L2** | Detection — anomaly, threat-pattern, IOC enrichment, correlation, fused into one verdict; analyst-feedback suppression runs *first* | label · threat type · severity · confidence · reasoning |
| **L3** | CIS benchmark mapping against real catalogs (Cisco ASA, IOS-XE 16/17, IOS-XR 7, NX-OS, Firepower, plus web) | benchmark ID + rationale + audit procedure + remediation |
| **L4** | CIS–CVSS advisor agent (LangGraph) — narrative, technique, CVSS metric proposal; deterministic fallback when no model is present | intent · narrative · CVSS handoff |
| **L5** | CVSS 3.1 scoring — metric mapping, impact mapping, scoring, validation, using the published equations | base score · severity band · vector string |
| **L6** | Response playbook — threat-specific containment, investigation, escalation | priority · containment · actions · escalation |

---

## The four differentiators

1. **Compliance evidence per incident, not per audit.** Every incident carries the
   CIS control it implicates with rationale and audit procedure. The artifact an
   auditor asks for is generated at detection time, not reconstructed a quarter
   later. CIS Controls v8.1 crosswalk to NIST CSF 2.0, NIST 800-53, ISO 27001,
   SOC 2, HIPAA and PCI DSS — one mapping, several regimes.

2. **Severity is computed, not guessed.** Layer 5 implements the CVSS 3.1
   equations. An LLM asked to rate severity gives a plausible number that drifts
   between runs; a formula gives one a regulator can re-derive from the vector
   string. *Verified against 7 published reference vectors — all exact.*

3. **The LLM degrades, it does not fail.** The agent layer is useful and optional.
   With no model reachable, Layer 4 returns the same field contract from
   deterministic rules. *Verified: the full pipeline runs with no model present.*

4. **Analyst feedback closes the loop.** Marking an incident a false positive
   writes a suppression rule that Layer 2 consults before running any engine on
   the next batch. Given 46% of alerts are false positives, this is the
   highest-leverage thing analyst judgement can do.
   *Verified end to end: feedback → rule → suppressed on re-run.*

---

## Proof — what actually runs today

Measured on the shipped sample telemetry, not projected:

- Full six-layer pipeline, ingest to stored incident — **≈1.3 s**
- Automated test suite — **19 / 19 passing**
- CVSS 3.1 vs published reference vectors — **7 / 7 exact**
- REST endpoints live and returning valid payloads — **9 / 9**
- Detection engines contributing signal per incident — **4 / 4**
- Incidents mapped to a named CIS control — **100%**
- Malformed / empty / non-JSON uploads — **4xx, never 500**
- Re-processing the same logs — **no duplicates** (IDs are content-derived)

---

## Market position

SOAR and AI-SOC vendors automate *triage*. Compliance platforms generate
*evidence*. In a regulated bank these are one job, because the notification clock
starts at determination and the auditor asks for the control mapping anyway.

SOAR sizing estimates vary widely by analyst house: roughly **$1.7–2.5B** in
2024–25 growing to about **$4.1B by 2030** at a 15.8% CAGR (Grand View Research),
or about **$7.4B by 2033** at a 14.4% CAGR (SkyQuest). Quote the range, not the
largest figure — the honest read is a mid-teens CAGR on a low-single-digit-billion
base, with adjacent SIEM and MDR spend an order of magnitude larger.

Competitive set: Splunk, Palo Alto XSIAM, Microsoft Sentinel, Google SecOps, Torq,
plus newer autonomous-triage entrants. All strong on orchestration and enrichment.
Comparatively rare: a deterministic severity score bound to a named control,
emitted per incident, that survives being handed to an auditor.

---

## What this is not — say it before you are asked

- **Detection is rule-based, not machine-learned.** Thresholds and field
  heuristics, not a trained model. Deliberate trade: every verdict is explainable
  and reproducible, which is what a regulated environment needs first.
- **The threat-intelligence feed is simulated.** A local indicator file, not a
  live commercial feed. Swapping it is an interface change, not an architecture one.
- **Behavioural baselines are per-run.** No persistent cross-run baseline, so
  "rare source IP" is judged within the batch being processed.
- **The advanced response package is a design, not a deployment.** HITL approval,
  ticketing and playbook evolution are unit-tested against mocks, not on the live
  path; they would need Elasticsearch, Redis and PostgreSQL to run for real.

---

## The four-minute demo script

1. **Open on the dashboard.** Ten incidents already scored — 3 critical, 5 high,
   2 medium. Point out that severity, CVSS score and priority disagree slightly
   and explain why: severity is the detection verdict, CVSS is computed impact,
   priority is the response decision. Three questions, three answers.
2. **Drill into the SQL injection.** Payload in the raw event → named technique →
   CVSS vector string. Offer to re-derive the score from the vector on the spot;
   that is the whole point of computing rather than guessing it.
3. **Open the CIS tab.** Control ID, rationale, audit procedure. Say the line:
   *this is the artifact the auditor asks for, generated at detection time.*
4. **Mark something a false positive, then re-run the pipeline.** The suppression
   rule appears; the alert does not come back. This is the loop that addresses the
   46% number from the opening.
5. **Upload a deliberately broken file.** Clean error, not a stack trace. Small
   thing, but it separates a demo from a system.

---

## Sources

1. IBM, *Cost of a Data Breach Report 2026* — study window Mar 2025–Feb 2026,
   602 organisations. <https://www.ibm.com/reports/data-breach>
2. CrowdStrike, *2026 Global Threat Report*.
   <https://www.crowdstrike.com/en-us/global-threat-report/>
3. SANS Institute, *2025 Detection & Response Survey*.
4. Microsoft / Omdia, *State of the SOC 2026*.
5. EU, *Digital Operational Resilience Act* (Reg. 2022/2554) and RTS on incident
   reporting, Art. 5.
6. CERT-In, *Directions under s.70B(6), IT Act 2000*, No. 20(3)/2022, 28 Apr 2022.
   <https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf>
7. OCC / Federal Reserve / FDIC, *Computer-Security Incident Notification
   Requirements for Banking Organizations*, 86 FR 66424.
8. US SEC, Release 33-11216, adopted 26 Jul 2023 (Item 1.05, Form 8-K).
   <https://www.sec.gov/newsroom/press-releases/2023-139>
9. Center for Internet Security, *CIS Critical Security Controls v8.1* (Jun 2024).
   <https://www.cisecurity.org/controls/v8-1>
10. Grand View Research; SkyQuest Technology — SOAR market sizing (cited as a
    range because the houses disagree materially).
11. Platform measurements taken directly from this repository, 22 August 2026.
