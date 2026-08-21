# SENTRA — Cyber Incident Response for Banking SOCs

Raw security telemetry in. A scored, control-mapped, playbook-ready incident out —
with the CIS control it violated, the ATT&CK technique it maps to, and a
defensible CVSS 3.1 score attached.

Then the part that matters most: **it works out which of those alerts are actually
the same intrusion.**

```
25 raw log records  →  4 investigations  →  1 active breach at Exfiltration
```

---

## The problem

An intrusion does not arrive as an intrusion. It arrives as a dozen unrelated
alerts across different hosts and hours, and the expensive part of an analyst's
job is realising they are one thing.

Meanwhile the clock is legal, not discretionary:

| Regime | Deadline | From |
| --- | --- | --- |
| EU DORA | **4 hours** | classifying an ICT incident as major |
| India CERT-In | **6 hours** | noticing the incident |
| US OCC / Fed / FDIC | **36 hours** | determining a notification incident occurred |
| US SEC Item 1.05 | **4 business days** | determining materiality |

Every one of those clocks starts at a *determination*. Determination is triage.
Triage is the bottleneck.

---

## What it does

Seven stages. Each is independently testable, and data flows strictly forward.

| Layer | Function | Output |
| --- | --- | --- |
| **L1** | Feature engineering — normalise heterogeneous formats, classify the log family, extract temporal / behavioural / statistical / network / web / IoT / identity features | normalised event + feature blocks |
| **L2** | Detection — anomaly scoring, threat-pattern matching, IOC enrichment, correlation, fused into one verdict. Analyst-feedback suppression runs *before* any engine | verdict · threat type · severity · confidence · reasoning |
| **L2** | MITRE ATT&CK mapping — technique and tactic per detection | `T1190` · Initial Access · lifecycle position |
| **L2.5** | **Campaign correlation** — groups alerts into intrusions and reports lifecycle progression | campaigns · kill chains · linkage evidence |
| **L3** | CIS benchmark mapping against real catalogs (Cisco ASA / IOS-XE 16 & 17 / IOS-XR 7 / NX-OS / Firepower, plus a web application catalog) | control ID · rationale · audit procedure · remediation |
| **L4** | Analysis agent (LangGraph) — narrative, intent, technique naming, CVSS metric proposal. Deterministic fallback when no model is present | intent · narrative · CVSS handoff |
| **L5** | CVSS 3.1 scoring — metric mapping, impact mapping, scoring, validation, using the published equations | base score · severity band · vector string |
| **L6** | Response playbook + **human-in-the-loop gate** — containment split by blast radius | priority · auto actions · gated actions · escalation |

### Campaign correlation is the interesting bit

Naive correlation groups by shared source IP. That misses the most important hop
in any real intrusion — once an attacker owns a host, *that host* becomes the
source of the next alert:

```
alert A:  203.0.113.55   →  dmz-web-01      SQL injection      (Initial Access)
alert B:  dmz-web-01     →  core-app-02     lateral movement   (Lateral Movement)
alert C:  core-app-02    →  db-core-01      lateral movement
alert D:  db-core-01     →  203.0.113.55    486 MB outbound    (Exfiltration)
```

A's victim is B's attacker. Chaining on that turns four unrelated-looking alerts
into one story with a direction of travel.

Two guards keep it honest, both regression-tested:

- **A scan is not a compromise.** The chain only extends from an incident that
  reached Initial Access or beyond. Without that gate, a scheduled vulnerability
  scan chains onto everything its targets later did — and an authorised scan ends
  up inside a breach campaign.
- **Shared infrastructure is not shared intent.** Grouping on "same asset
  targeted" bridges every unrelated cluster into one useless mega-campaign,
  because in a real network everything touches the same servers.

### The human-in-the-loop gate

In a bank, isolating the host that clears card transactions can cause a worse
outage than the intrusion — and an outage on a regulated service is itself a
reportable event. So containment is split by **blast radius, not severity**: a
critical verdict does not earn the right to break production.

```
Blocking an attacker IP at the edge      →  auto      (contained, reversible)
Isolating db-core-01                     →  approval  (service-affecting)
Disabling the payments service account   →  approval  (service-affecting)
```

Roughly 65% of containment actions auto-execute on the demo dataset; the rest wait
for a human who is told exactly why they were asked.

---

## Quick start

```bash
# Backend
python -m venv .venv && source .venv/bin/activate    # Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn api_server:app --reload --port 8000          # docs at /docs

# Frontend (new terminal)
cd Frontend && npm install && npm run dev            # http://localhost:3000
```

`/` redirects to the dashboard. The shipped `soc_incidents.db` already contains a
processed scenario, so the dashboard has data on first load.

### Run the pipeline offline

```bash
python dev_run.py                       # the multi-stage banking intrusion
python dev_run.py path/to/your.json     # any JSON or JSONL log file
```

Prints the verdict spread, the campaigns it reconstructed, the consolidation
ratio, and per-layer timing. Completes in about 0.15 s on the 25-record scenario
and is idempotent — incident IDs derive from log content, so re-running updates
incidents in place instead of duplicating them.

### Tests

```bash
pytest -q        # 49 tests
```

### Optional: local LLM for Layer 4

```bash
ollama serve && ollama pull mistral
```

**Entirely optional.** With no model reachable, Layer 4 returns the same field
contract from deterministic rules. A SOC tool that stops working when an inference
endpoint is down is not a SOC tool.

The dashboard reads the backend through Next.js route handlers, defaulting to
`http://127.0.0.1:8000`. Point it elsewhere with
`NEXT_PUBLIC_SOC_API_URL=http://host:8000 npm run dev`.

---

## API

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | Service banner and endpoint index |
| `POST` | `/run-pipeline` | Upload JSON/JSONL logs, run every layer |
| `GET` | `/api/incidents` | All stored incidents |
| `GET` | `/api/incidents/{id}` | One incident |
| `POST` | `/api/incidents/{id}/action` | Update status |
| `DELETE` | `/api/incidents` | Clear incidents and campaigns |
| `GET` | `/api/campaigns` | Correlated campaigns, worst first |
| `GET` | `/api/campaigns/{id}` | One campaign with its member incidents |
| `GET` | `/api/metrics` | SOC value metrics computed from stored state |
| `POST` | `/api/incidents/{id}/feedback` | Analyst feedback; `false_positive` writes a suppression rule |
| `GET` | `/api/incidents/{id}/feedback` | Feedback history |
| `GET` | `/api/suppression-rules` | Active suppression rules |
| `GET` | `/api/approvals` | Containment actions queued for sign-off |
| `POST` | `/api/incidents/{id}/approvals` | Queue an action for approval |
| `POST` | `/api/approvals/{id}/decision` | Approve or reject |
| `GET` | `/api/incidents/{id}/report` | Incident as a Markdown audit record |
| `GET` | `/api/campaigns/{id}/report` | Campaign as a Markdown audit report |

---

## The feedback loop actually closes

Marking an incident a false positive writes a suppression rule that Layer 2
consults **before running any engine** on the next batch. The same benign pattern
stops arriving.

```bash
# Mark the scheduled vulnerability scan a false positive, then re-run
curl -X POST localhost:8000/api/incidents/<id>/feedback \
  -H 'Content-Type: application/json' \
  -d '{"label":"false_positive","reason":"authorized_scan"}'

python dev_run.py     # those alerts now come back labelled 'suppressed'
```

---

## Layout

```
api_server.py            FastAPI app — endpoints only
pipeline.py              the layer sequence, in one place
dev_run.py               offline runner
frontend_formatter.py    pipeline output -> dashboard contract
soc_metrics.py           value metrics computed from stored state
audit_report.py          Markdown audit records
db_manager.py            SQLite: incidents, feedback, campaigns, approvals
demo_attack_scenario.json  the 25-record banking intrusion

layer_1_feature_engineering/   7 feature engines
layer_2_detection/            4 detection engines + suppression
  mitre_mapper.py             ATT&CK techniques and tactics
  campaign_correlator.py      Layer 2.5
layer_3_cis/                  CIS/OWASP catalogs + matcher
layer_4_ai_analysis/          LangGraph agent + rule-based fallback
layer_5_cvss/                 4 CVSS engines
layer_6_response/             playbooks + human-in-the-loop gate
tests/                        cross-layer tests
Frontend/                     Next.js 16 dashboard
```

---

## Verified, not asserted

Measured on the shipped scenario:

| | |
| --- | --- |
| Full pipeline, ingest to stored incident | **≈0.15 s** (25 records) |
| Test suite | **49 / 49** |
| CVSS 3.1 vs published reference vectors | **7 / 7 exact** |
| Incidents mapped to a named CIS control | **100%** |
| Incidents mapped to an ATT&CK technique | **84%** |
| Detection engines contributing per actionable incident | **3–4 of 4** |
| Benign business traffic correctly not flagged | **4 / 4** |
| Malformed / empty / non-JSON uploads | **4xx, never 500** |
| Re-processing the same logs | **no duplicates** |

---

## Known limitations

Stated plainly, because they matter when reading the output.

- **Detection is rule-based, not machine-learned.** Anomaly scoring uses
  thresholds and field heuristics, not a trained model. A deliberate trade:
  every verdict is explainable and reproducible, which is what a regulated
  environment needs first.
- **The threat-intelligence feed is simulated.** `layer_2_detection/mappings/ioc_feed.json`
  is a local indicator file, not a live commercial feed. Swapping it is an
  interface change, not an architecture change.
- **Behavioural baselines are per-run.** There is no persistent cross-run
  baseline, so "rare source IP" is judged within the batch being processed.
- **Approved containment actions are recorded, not executed.** The gate, the
  queue and the decision are real and persisted; there is no EDR or firewall
  integration behind them yet.
- **Analyst time saved is modelled, not measured.** It depends on manual triage
  time, which cannot be observed from inside this system. The assumption is
  returned in the API response next to the number so it can be challenged and
  recomputed.

---

## Stack

Python · FastAPI · SQLite · Pydantic · LangGraph · Next.js 16 · React 19 ·
TypeScript · Tailwind 4
