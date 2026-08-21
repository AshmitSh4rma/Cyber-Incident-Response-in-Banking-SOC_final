# SENTRA — Pitch Notes

**Automated incident response for banking Security Operations Centers.**

Raw security telemetry in; a scored, control-mapped, playbook-ready incident out —
with the CIS control it violated and a defensible CVSS 3.1 score attached.
Six analysis layers, roughly one second, no analyst keystrokes.

---

## The one-line thesis

> An intrusion doesn't arrive as an intrusion. It arrives as **twenty-five
> unrelated alerts** across four hosts and four hours.
>
> Attackers break out of the first host in **29 minutes**. EU DORA gives a bank
> **4 hours** to notify. Meanwhile **46%** of the analyst's queue is false
> positives.
>
> The bottleneck is not detection. It is *determination* — and every regulatory
> clock in banking starts the moment determination happens.

```
25 raw alerts  →  4 investigations  →  1 breach at Exfiltration     (0.148s)
```

---

## The centrepiece: campaign correlation

Correlating by shared source IP is the obvious approach, and it misses the most
important hop in any real intrusion: **once an attacker owns a host, that host
becomes the source of the next alert.**

| # | Stage | Technique | What happened |
| - | ----- | --------- | ------------- |
| 1 | Reconnaissance | `T1595.001` | 203.0.113.55 port-scans dmz-web-01 |
| 2 | Initial Access | `T1190` | SQL injection on `/retail/login` (sqlmap UA) |
| 3 | Persistence | `T1505.003` | webshell uploaded to `/admin/upload.php` |
| 4 | Lateral Movement | `T1021` | dmz-web-01 → core-app-02 → db-core-01, as `svc_payments` |
| 5 | Command and Control | `T1071.001` | periodic HTTPS callbacks to 185.14.22.91 |
| 6 | Exfiltration | `T1041` | db-core-01 → 203.0.113.55, **486 MB** over 3m35s |

Six of fifteen ATT&CK stages — **93% of the attack lifecycle** — reconstructed
from nine rows that arrived separately in a queue. Campaign severity is escalated
above any individual member, because a chain spanning six stages is worse than the
sum of its alerts.

**Two guards keep it honest**, both regression-tested:

- **A scan is not a compromise.** The chain only extends from an incident that
  reached Initial Access or beyond — so an authorised vulnerability scanner cannot
  chain onto everything its targets later did. On the demo data it stays in its own
  harmless cluster.
- **Shared infrastructure is not shared intent.** Grouping on "same asset
  targeted" collapses every unrelated cluster into one useless mega-campaign,
  because in a real network everything touches the same servers.

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

## What it does — seven stages

| Layer | Function | Output |
| ----- | -------- | ------ |
| **L1** | Feature engineering — normalise, classify log family, extract temporal / behavioural / statistical / network / web / IoT / identity features | normalised event + feature blocks |
| **L2** | Detection — anomaly, threat-pattern, IOC enrichment, correlation, fused into one verdict; analyst-feedback suppression runs *first* | verdict · threat type · severity · confidence · reasoning |
| **L2** | MITRE ATT&CK mapping — technique + tactic + lifecycle position | `T1190` · Initial Access · stage 3/15 |
| **L2.5** | **Campaign correlation** — groups alerts into intrusions, reports progression | campaigns · kill chains · linkage evidence |
| **L3** | CIS benchmark mapping against real catalogs (Cisco ASA, IOS-XE 16/17, IOS-XR 7, NX-OS, Firepower, plus web) | control ID + rationale + audit procedure + remediation |
| **L4** | Analysis agent (LangGraph) — narrative, intent, CVSS metric proposal; deterministic fallback with no model | intent · narrative · CVSS handoff |
| **L5** | CVSS 3.1 scoring — metric mapping, impact mapping, scoring, validation | base score · severity band · vector string |
| **L6** | Response playbook + **human-in-the-loop gate** | priority · auto actions · gated actions · escalation |

---

## The differentiators

1. **Correlation follows the compromise, not just the IP.** Chaining a host from
   victim to attacker is what turns a queue into an attack chain with a direction
   of travel — and what tells an analyst the intruder reached the database rather
   than bounced off the web tier. *9 alerts → 1 campaign at 93% progression.*

2. **Compliance evidence per incident, not per audit.** Every incident carries the
   CIS control it implicates with rationale and audit procedure, exportable as a
   Markdown record. The artifact an auditor asks for is generated at detection
   time, not reconstructed a quarter later. CIS Controls v8.1 crosswalk to NIST
   CSF 2.0, NIST 800-53, ISO 27001, SOC 2, HIPAA and PCI DSS — one mapping,
   several regimes. *100% of incidents carry a named control.*

3. **Severity is computed, not guessed.** The CVSS 3.1 equations, implemented
   directly. An LLM asked to rate severity gives a plausible number that drifts
   between runs; a formula gives one a regulator can re-derive from the vector
   string. *7 of 7 published reference vectors — exact.*

4. **The gate is on blast radius, not severity.** Isolating the host that clears
   card transactions can cause a worse outage than the intrusion — and an outage
   on a regulated service is itself reportable. Blocking an attacker IP
   auto-executes; isolating a core banking host waits for a human who is shown
   exactly why they were asked. A critical verdict does not earn the right to
   break production. *65% of containment actions auto-execute.*

5. **The LLM degrades, it does not fail.** With no model reachable, Layer 4
   returns the same field contract from deterministic rules. A SOC tool that stops
   working when an inference endpoint is down is not a SOC tool.

6. **The feedback loop actually closes.** Marking an incident a false positive
   writes a suppression rule that Layer 2 consults *before running any engine* on
   the next batch. Given 46% of alerts are false positives, this is the
   highest-leverage thing analyst judgement can do — and here it compounds instead
   of evaporating into a ticket comment.

---

## Proof — what actually runs today

Measured on the shipped scenario, not projected:

| | |
| --- | --- |
| Full seven-stage pipeline, 25 records | **0.148 s** |
| Automated test suite | **49 / 49** |
| CVSS 3.1 vs published reference vectors | **7 / 7 exact** |
| Incidents mapped to a named CIS control | **100%** |
| Incidents mapped to an ATT&CK technique | **84%** |
| Actionable alerts → investigations | **21 → 4 (5.2:1)** |
| Benign business traffic correctly not flagged | **4 / 4** |
| Authorised scan kept out of the breach campaign | **yes** |
| Analyst time saved on this window (modelled) | **6.0 hours** |
| Malformed / empty / non-JSON uploads | **4xx, never 500** |
| Re-processing the same logs | **no duplicates** |

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
  live commercial feed. Swapping it is an interface change, not architecture.
- **Behavioural baselines are per-run.** No persistent cross-run baseline, so
  "rare source IP" is judged within the batch being processed.
- **Approved containment is recorded, not executed.** The gate, the queue and the
  decision are real and persisted; there is no EDR or firewall integration behind
  them yet.
- **Analyst time saved is modelled, not measured.** It depends on manual triage
  time, which cannot be observed from inside the system. The assumption ships in
  the API response next to the number so it can be challenged and recomputed.

---

## The four-minute demo script

1. **Open the dashboard.** Read the header: 25 alerts ingested, 4 investigations,
   5.2:1 consolidation, 6 hours saved. Four benign events filtered with no analyst
   involvement.
2. **Click the red banner.** The moment. One campaign, nine alerts, six ATT&CK
   stages, 93% of the lifecycle, ending at Exfiltration with 486 MB out of the core
   banking database. Trace it: external IP → DMZ web → app tier → database → out.
3. **Show the correlation basis.** Not magic — *"dmz-web-01 was compromised at
   Initial Access, then became the source of the next activity."* Then show the
   scheduled scan in its own harmless cluster and explain why it is not in the breach.
4. **Open the SQL injection incident.** Payload in the raw event, `T1190` with its
   lifecycle position, the CIS control with its audit procedure, the CVSS vector.
   Offer to re-derive the score from the vector on the spot.
5. **Scroll to the containment plan.** Blocking the attacker IP is green and
   automatic. Isolating `db-core-01` is amber and waiting, because it would take a
   customer-facing banking service down. Approve it live.
6. **Export the audit report.** Markdown, full chain, every control and technique.
   Say the line: *this is what the auditor asks for, generated at detection time.*
7. **Mark the scan a false positive and re-run.** The suppression rule appears;
   those alerts return labelled suppressed. This is the loop that addresses the 46%.

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
9. MITRE ATT&CK Enterprise — 15 tactics, verified against the current matrix
   (TA0005 is "Stealth", TA0112 "Defense Impairment").
   <https://attack.mitre.org/tactics/enterprise/>
10. Center for Internet Security, *CIS Critical Security Controls v8.1* (Jun 2024).
    <https://www.cisecurity.org/controls/v8-1>
11. Grand View Research; SkyQuest Technology — SOAR market sizing (cited as a
    range because the houses disagree materially).
12. Platform measurements taken directly from this repository, 22 August 2026.
