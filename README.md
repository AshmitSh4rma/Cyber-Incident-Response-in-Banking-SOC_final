# SENTRA — Cyber Incident Response for Banking SOCs

**In one sentence:** it reads a bank's security logs, works out which alerts are
actually the same break-in, and tells you how long you have left to report it to
the regulator.

**For the technical reader:** a seven-stage pipeline that maps every detection to a
CIS control and an ATT&CK technique, computes a CVSS 3.1 score by formula,
reconstructs multi-host intrusions by chaining compromised hosts, and gates
containment on blast radius.

```
25 raw log records  →  4 investigations  →  1 active breach at Exfiltration
                                            → 3h 59m left to notify the EU regulator
```

Measured on the shipped scenario, end to end, in 0.16 s.

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

| Stage | In plain terms | Technically |
| --- | --- | --- |
| **L1** | Reads logs from anything and puts them in one shape | Normalisation, log-family classification, 7 feature engines |
| **L2** | Decides whether each event is a real threat | Anomaly, threat-pattern, IOC and correlation engines fused into one verdict; analyst-feedback suppression runs first |
| **L2** | Names the behaviour the way the industry names it | MITRE ATT&CK technique + tactic + lifecycle position |
| **L2.5** | **Works out which alerts are the same break-in** | Campaign correlation over a compromise chain |
| **L3** | Says which security rule this breaks | CIS / OWASP benchmark retrieval with rationale and audit procedure |
| **L4** | Writes it up for a human | Deterministic incident analyst; optional local-LLM enrichment |
| **L5** | Scores how bad it is, consistently | CVSS 3.1 base score computed from the published equations |
| **L6** | Says what to do, and what needs a person | Threat-specific playbook + blast-radius approval gate |
| **Clock** | **Says how long until you must tell the regulator** | Reportability assessment + per-regime countdown |
| **Settings** | **Lets the bank change any of the above without a developer** | 22 declared settings read at the point of use; validated, previewable, reversible |

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

### The regulatory clock

Every incident-response tool tells you how bad something is. In a regulated bank
the more urgent question is **how long you have left to tell someone** — a missed
notification deadline is a violation in its own right, independent of what the
attacker achieved.

Those clocks do not start when the attack starts. They start at a *determination*
— "classified as a major ICT incident", "determined to be material", "noticed" —
which is exactly the moment this pipeline produces a verdict. So it starts the
clock automatically:

```
CMP-003  Exfiltration, critical   →  reportable (high confidence)
           EU DORA          4 hours         3h 59m remaining
           India CERT-In    6 hours         5h 59m remaining
           US OCC/Fed/FDIC  36 hours        1d 11h remaining
           US SEC 8-K       4 business days 3d 23h remaining

CMP-001  Reconnaissance, medium  →  not reportable
           "Activity has not progressed past reconnaissance and does not meet a
            materiality threshold on its own."
```

The threshold is deliberately conservative and always explains itself: data
plausibly gone is enough on its own; otherwise it wants both a foothold *and*
material severity, because a high-severity probe that never landed is a security
event, not a reportable operational incident.

**This is decision support, not a compliance filing and not legal advice.** The
pipeline flags what looks reportable and shows the deadline each regime would
impose; a bank's compliance function makes the determination and owns the filing.
That disclaimer ships in every API response.

---

## Nothing here needs a developer to change

Every number that decides how this system behaves was a Python literal, and a
system whose risk appetite is a literal cannot be deployed twice. **Settings**
(`/settings`) exposes 22 of them — thresholds, severity policy, jurisdiction,
response autonomy, the savings model, and console defaults — with no code change
and no restart.

The mechanism is small on purpose:

- **Declared, not hardcoded twice.** `soc_config.py` holds one list of settings,
  each carrying its plain-English question, its bounds, and a sentence on what
  observably changes when you move it. The console renders from that list, so
  adding a setting server-side makes it appear in the UI with no frontend change.
- **Read at the point of use.** Nothing is captured at import, so a saved change
  applies to the next event without a restart. `get()` re-reads the file when it
  changes on disk, which is what lets the API server and the offline runner share
  one source of truth.
- **Applied whole or not at all.** Every problem in a patch is reported at once,
  keyed by setting, and nothing is written if any of them fails. A half-applied
  configuration is the one failure mode that leaves an operator confidently wrong
  about their own system.
- **Only differences are stored.** `soc_config.json` holds overrides, so "what
  has been changed here" is answerable by comparison, and a later release can
  re-tune a default without silently inheriting an old one.

### Refusals that matter more than the bounds

Per-field bounds are the easy half. Two cross-field rules exist because the
values are coupled, and breaking the coupling fails *silently*:

- The confidence ceiling must stay above the threshold at which a verdict becomes
  `malicious`. Set it lower and no incident can ever be labelled malicious again —
  a total change in behaviour with no error anywhere.
- Reviewing an investigation cannot cost as much as triaging every alert by hand,
  or the dashboard reports a negative saving as a positive one.

### "What would this do?"

The part that makes the rest safe to touch. `POST /api/config/preview` runs the
demo records through all seven layers twice — once as configured, once with the
candidate applied — and returns both outcomes and their difference. Nothing is
saved.

```
Withhold automatic IP blocking       actions_automatic         31 -> 17
                                     actions_needing_approval  25 -> 39
Only CERT-In applies to us           notification_deadlines     8 -> 2
Analyst triage 15 -> 25 minutes      hours_saved              6.0 -> 10.2
Failed-login threshold 3 -> 25       severity  medium 8 · high 10 -> medium 12 · high 6
Tighten the exfiltration ratio to 5  actionable                21 -> 22
                                     (a customer downloading their own statement
                                      becomes a critical exfiltration alert)
Compromise gate at Reconnaissance    campaigns                  3 -> 2
                                     investigations             4 -> 3
```

A setting that changes only what the console shows says so instead of running the
pipeline and reporting no difference, which would read as the control being inert.

Layer 1 accumulates per-source history in module state, so `pipeline.reset_state()`
runs before each of the two comparison runs. Without it the second inherits the
first one's traffic and the comparison measures the wrong thing.


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
ratio, and per-layer timing. Completes in about 0.09 s on the 25-record scenario
and is idempotent — incident IDs derive from log content, so re-running updates
incidents in place instead of duplicating them.

### Tests

```bash
pytest -q        # 177 tests
```

### Optional: local LLM for Layer 4

```bash
ollama serve && ollama pull mistral
```

**Entirely optional.** The deterministic analyst is the baseline and always
produces a complete result; a model, when reachable, writes a better narrative and
its output is only used if it passes validation against the same closed
vocabularies (an out-of-vocabulary `attack_vector` would silently corrupt the CVSS
score downstream).

This layer used to be wrapped in LangGraph. It was a single-node graph — entry,
one function, END — which is framework decoration rather than agency, so the
framework was removed and the capability kept. A SOC tool that stops working when
an inference endpoint is down is not a SOC tool.

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
| `GET` | `/api/notifications` | Everything on a reporting clock, soonest deadline first |
| `GET` | `/api/regimes` | The notification regimes and their deadlines |
| `POST` | `/api/incidents/{id}/feedback` | Analyst feedback; `false_positive` writes a suppression rule |
| `GET` | `/api/incidents/{id}/feedback` | Feedback history |
| `GET` | `/api/suppression-rules` | Active suppression rules |
| `GET` | `/api/approvals` | Containment actions queued for sign-off |
| `POST` | `/api/incidents/{id}/approvals` | Queue an action for approval |
| `POST` | `/api/approvals/{id}/decision` | Approve or reject |
| `GET` | `/api/incidents/{id}/report` | Incident as a Markdown audit record |
| `GET` | `/api/campaigns/{id}/report` | Campaign as a Markdown audit report |
| `GET` | `/api/config` | Settings schema, current values, what differs from default, recent changes |
| `PUT` | `/api/config` | Apply a change; `422` with per-field messages and nothing written if invalid |
| `POST` | `/api/config/preview` | Run the pipeline twice and return the difference, saving nothing |
| `POST` | `/api/config/reset` | Return every setting to its shipped default |

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
regulatory_clock.py      reportability + per-regime notification deadlines
soc_metrics.py           value metrics computed from stored state
audit_report.py          Markdown audit records
db_manager.py            SQLite: incidents, feedback, campaigns, approvals
demo_attack_scenario.json  the 25-record banking intrusion

layer_1_feature_engineering/   7 feature engines
layer_2_detection/            4 detection engines + suppression
  mitre_mapper.py             ATT&CK techniques and tactics
  campaign_correlator.py      Layer 2.5
layer_3_cis/                  CIS/OWASP catalogues + IDF-weighted matcher
soc_config.py                 the 22 runtime settings: schema, validation, storage
layer_4_ai_analysis/          deterministic analyst + optional LLM enrichment
layer_5_cvss/                 4 CVSS engines
layer_6_response/             playbooks + blast-radius approval gate
tests/                        cross-layer tests
Frontend/                     Next.js 16 dashboard (30 source files)
```

### On the frontend

Four screens, deliberately: the **queue** (what to look at first), a **campaign**
(how one intrusion unfolded), an **investigation** (everything about one alert in
one place), and **compliance** (what is on a clock). Plus scenario replay.

The investigation used to be five tabbed pages. Once an alert becomes a case the
job is comparing evidence, and evidence you have to navigate between is evidence
you do not compare — so it is one workspace now.

Every technical panel carries a one-sentence plain-language note, so the screens
read for a risk officer as well as an analyst.

Colour does exactly two jobs and never mixes them: cyan is interactive, and the
severity ramp is status-only. Because severity is red/orange/yellow — hues that
are not separable under colour-vision deficiency — **every severity indicator also
carries its word**, enforced by the shared `SeverityChip`. Contrast for every
token and mark was measured against the actual surfaces, not eyeballed; the
numbers are in `app/globals.css`.

---

## Verified, not asserted

Measured on the shipped scenario:

| | |
| --- | --- |
| Full pipeline, 25 records ingest to stored incident | **0.09 s** (median of 7) |
| Test suite | **177 / 177** |
| CVSS 3.1 vs NVD-published reference vectors | **9 / 9 exact** |
| CVSS 3.1 vs an independent implementation, whole metric space | **2,592 / 2,592** |
| Incidents mapped to a named CIS control | **100%** |
| Incidents mapped to an ATT&CK technique | **84%** |
| Actionable alerts → investigations | **21 → 4 (5.2:1)** |
| Campaigns correctly flagged reportable | **2 of 3** (recon cluster correctly excluded) |
| Benign business traffic correctly not flagged | **4 / 4** |
| Containment actions safe to automate | **65%** |
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
- **Notification clocks are decision support, not a filing.** The reportability
  threshold is a documented heuristic, and the SEC countdown approximates four
  business days as 96 calendar hours, so it reads pessimistically across a
  weekend. Compliance owns the determination.
- **Analyst time saved is modelled, not measured.** It depends on manual triage
  time, which cannot be observed from inside this system. The assumption is
  returned in the API response next to the number so it can be challenged and
  recomputed.

---

## Stack

Python · FastAPI · SQLite · Next.js 16 · React 19 · TypeScript · Tailwind 4

Optional: Ollama for local LLM narrative enrichment.
