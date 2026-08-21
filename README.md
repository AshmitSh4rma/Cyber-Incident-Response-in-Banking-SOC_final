# Cyber Incident Response in Banking SOC

A full-stack **Security Operations Center (SOC) incident response platform** designed for banking-style cyber incident workflows.

The system takes raw security logs, processes them through a multi-layer SOC pipeline, detects suspicious activity, maps incidents to CIS benchmark controls, generates security recommendations, prepares CVSS scoring context, recommends response actions, and displays everything in an analyst-friendly dashboard.

---

## Overview

Banking environments generate large volumes of security telemetry from networks, web applications, identity systems, endpoints, databases, and cloud infrastructure. SOC analysts often need to manually connect these signals, identify threats, assess impact, and decide the correct response action.

This project solves that problem by building a structured incident response pipeline that converts raw logs into actionable SOC intelligence.

The platform helps answer key SOC questions:

* What happened?
* Which user, IP, host, or service was affected?
* Is the event suspicious or malicious?
* What type of threat does it represent?
* Which CIS benchmark or security control is relevant?
* What is the likely business and technical impact?
* What severity score should be assigned?
* What should the SOC team do next?

---

## What This Project Solves

This project focuses on reducing manual SOC triage effort by automating the core stages of incident analysis and response.

It helps with:

* Log ingestion and normalization
* Feature extraction from raw events
* Threat and anomaly detection
* IOC and correlation analysis
* CIS benchmark recommendation
* CIS-based remediation guidance
* CVSS-style severity scoring
* Response playbook recommendation
* Analyst-friendly dashboard visualization
* Incident storage, review, and feedback tracking

The goal is to simulate how a banking SOC can move from raw telemetry to structured incident decisions.

---

## Key Features

* Multi-layer SOC pipeline architecture
* FastAPI backend for log upload and incident APIs
* Next.js frontend dashboard
* SQLite incident database
* Feature engineering for network, web, identity, IoT, and behavioral signals
* Detection layer with anomaly, threat-pattern, IOC, and correlation engines
* CIS benchmark mapping and remediation guidance
* Single-purpose AI recommendation agent for CIS and CVSS handoff
* CVSS-style scoring and severity classification
* Response playbook recommendation layer
* Analyst feedback and action tracking
* Sample incidents and generated output for demo use

---

## Agentic Component

The project includes a focused agentic layer called the:

## SENTRA CIS–CVSS Advisor Agent

Unlike a generic chatbot, this agent performs one practical SOC function:

> It takes the detection output and CIS benchmark mapping, generates a CIS-based security recommendation, and prepares structured CVSS scoring inputs for the next pipeline layer.

The agent helps bridge the gap between detection, security control mapping, and severity assessment.

### Agent Responsibilities

* Read the detected threat and supporting signals
* Identify the relevant CIS benchmark or control
* Generate a remediation recommendation
* Explain why the benchmark applies
* Prepare CVSS metric suggestions
* Forward structured context to the CVSS scoring layer

This keeps the system agentic through actual pipeline behavior rather than visual gimmicks.

---

## Architecture

```mermaid
flowchart TD
    A[Raw Logs / Uploaded JSON] --> B[FastAPI Backend]
    B --> C[Layer 1: Feature Engineering]
    C --> D[Layer 2: Detection]
    D --> E[Layer 3: CIS Benchmark Mapping]
    E --> F[SENTRA CIS-CVSS Advisor Agent]
    F --> G[Layer 5: CVSS Scoring]
    G --> H[Layer 6: Response Recommendation]
    H --> I[Frontend Formatter]
    I --> J[(SQLite Incident Database)]
    J --> K[Next.js SOC Dashboard]
    K --> L[Analyst Review / Feedback / Actions]
    L --> J
```

---

## Layer-by-Layer Pipeline

### Layer 1: Feature Engineering

This layer takes raw logs and converts them into structured security events.

It performs:

* Log parsing
* Field normalization
* Timestamp normalization
* Log type classification
* Temporal feature extraction
* Behavioral feature extraction
* Network feature extraction
* Web feature extraction
* Identity feature extraction
* IoT feature extraction

The output is passed to the detection engine.

---

### Layer 2: Detection

This layer determines whether an event is benign, suspicious, or malicious.

It performs:

* Anomaly detection
* Threat pattern matching
* IOC enrichment
* Observable extraction
* Correlation analysis
* Suppression rule checks
* Final detection fusion

The output includes:

* Detection label
* Severity
* Confidence score
* Threat type
* Supporting signals
* Reasoning

---

### Layer 3: CIS Benchmark Mapping

This layer maps detected incidents to relevant CIS benchmark controls and security recommendations.

It provides:

* CIS benchmark ID
* Security framework
* Control title
* Control description
* Remediation guidance

This helps connect technical detections to recognized security best practices.

---

### Agent Layer: CIS–CVSS Advisor

This layer acts as a focused recommendation agent between CIS mapping and CVSS scoring.

It provides:

* CIS-based recommendation
* Recommendation rationale
* Matched benchmark context
* CVSS metric handoff
* Downstream readiness status

This allows the next layers to work with structured, explainable security context.

---

### Layer 5: CVSS Scoring

This layer estimates incident severity using CVSS-style logic.

It provides:

* Base score
* Severity rating
* CVSS vector string
* Exploitability mapping
* Impact mapping

This helps prioritize incidents based on risk.

---

### Layer 6: Response Recommendation

This layer recommends what the SOC team should do next.

It provides:

* Response priority
* Containment steps
* Recommended actions
* Playbook-style response guidance

Example response actions include:

* Block suspicious source IP
* Review exposed firewall rules
* Enable IDS alerts
* Isolate affected host
* Reset user credentials
* Escalate to SOC Tier-2

---

## Folder Structure

```text
Cyber-Incident-Response-in-Banking-SOC_final/
|
|-- Frontend/
|   |-- app/
|   |-- components/
|   |-- hooks/
|   |-- lib/
|   |-- public/
|
|-- layer_1_feature_engineering/
|   |-- engine_1_temporal/
|   |-- engine_2_behavioral/
|   |-- engine_3_statistical/
|   |-- engine_4_network/
|   |-- engine_5_web/
|   |-- engine_6_iot/
|   |-- engine_7_identity/
|
|-- layer_2_detection/
|   |-- engine_1_anomaly/
|   |-- engine_2_threat_analysis/
|   |-- engine_3_ioc_enrichment/
|   |-- engine_4_correlation/
|   |-- mappings/
|
|-- layer_3_cis/
|   |-- engines/
|   |-- mappings/
|   |-- tuxSOC-layer_CIS/
|
|-- layer_4_ai_analysis/
|   |-- agent/
|
|-- layer_5_cvss/
|   |-- engine_1_metric_mapping/
|   |-- engine_2_impact_mapping/
|   |-- engine_3_scoring/
|   |-- engine_4_validation/
|   |-- mappings/
|
|-- layer_6_response/
|   |-- response_layer/
|   |-- tests/
```

---

## Tech Stack

### Backend

* Python
* FastAPI
* SQLite
* Pydantic
* Uvicorn

### Frontend

* Next.js
* React
* TypeScript
* Tailwind CSS

### Security Pipeline

* Rule-based detection
* Anomaly scoring
* IOC enrichment
* CIS benchmark mapping
* CIS–CVSS recommendation agent
* CVSS-style scoring
* Response playbook logic

---

## How to Run the Project

### 1. Clone the Repository

```bash
git clone https://github.com/atharvbellikar/Cyber-Incident-Response-in-Banking-SOC_final.git
cd Cyber-Incident-Response-in-Banking-SOC_final
```

---

### 2. Set Up the Backend

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Or on Windows:

```bash
.\.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the backend server:

```bash
uvicorn api_server:app --reload --host 127.0.0.1 --port 8000
```

Backend API documentation will be available at:

```text
http://127.0.0.1:8000/docs
```

---

### 2b. Optional: Local LLM for Layer 4

Layer 4 will use a local [Ollama](https://ollama.com) model for incident narratives
if one is running:

```bash
ollama serve
ollama pull mistral
```

**This is optional.** With no Ollama available, Layer 4 falls back to a
deterministic rule-based analyst that produces the same set of fields (intent,
summary, narrative, CVSS metric suggestions). The pipeline never fails because a
model is missing — it degrades to explainable rules. Verify either path with:

```bash
pytest layer_4_ai_analysis/test_layer3_e2e.py -v
```

---

### 3. Set Up the Frontend

Open a new terminal:

```bash
cd Frontend
npm install
npm run dev
```

Open the frontend at:

```text
http://localhost:3000
```

`/` redirects to the incident dashboard at `/dashboard`.

The dashboard proxies all API calls to the FastAPI backend through Next.js route
handlers, defaulting to `http://127.0.0.1:8000`. Point it elsewhere with an
environment variable:

```bash
NEXT_PUBLIC_SOC_API_URL=http://192.168.1.20:8000 npm run dev
```

---

## Running the Test Suite

```bash
pytest -q
```

19 tests covering Layer 2 detection and suppression, the Layer 2 -> Layer 3 CIS
integration, the Layer 4 rule-based fallback contract, and the Layer 6 response
orchestrator / workflow / playbook evolution.

---

## Run the Whole Pipeline Offline

To generate all layer outputs and seed the incident database without starting any
server:

```bash
python dev_run.py
```

This reads `layer_1_feature_engineering/sample_logs.json` and writes
`layer1_output.json`, `layer2_output.json`, `layer3_output.json`,
`frontend_output.json`, `Frontend/public/frontend_output.json`, and
`soc_incidents.db`. It completes in about one second and is idempotent — incident
IDs are derived from log content, so re-running updates incidents in place
instead of creating duplicates.

---

## How to Use

1. Start the backend server.
2. Start the frontend dashboard.
3. Open the dashboard in the browser.
4. Upload a JSON log file or use the included sample incident data.
5. Review generated incidents.
6. Open an incident to inspect:

   * Raw event details
   * Feature engineering output
   * Detection output
   * CIS benchmark recommendation
   * CIS–CVSS advisor recommendation
   * CVSS score
   * Response recommendation
7. Submit analyst feedback or update response actions if needed.

---

## Main Backend API Endpoints

| Method   | Endpoint                             | Description                               |
| -------- | ------------------------------------ | ----------------------------------------- |
| `GET`    | `/`                                  | Service banner and endpoint index         |
| `POST`   | `/run-pipeline`                      | Upload logs and run the full SOC pipeline |
| `GET`    | `/api/incidents`                     | Get all stored incidents                  |
| `GET`    | `/api/incidents/{event_id}`          | Get one incident by ID                    |
| `POST`   | `/api/incidents/{event_id}/action`   | Update incident action/status             |
| `POST`   | `/api/incidents/{event_id}/feedback` | Submit analyst feedback                   |
| `GET`    | `/api/incidents/{event_id}/feedback` | Get analyst feedback                      |
| `POST`   | `/api/simulate`                      | Add simulated incident events             |
| `DELETE` | `/api/incidents`                     | Clear stored incidents                    |
| `GET`    | `/api/suppression-rules`             | View suppression rules                    |

---

## Example Incident Output

Each processed incident can include:

* Event ID
* Timestamp
* Source IP
* Destination IP
* Affected user or host
* Threat type
* Detection confidence
* Severity
* CIS benchmark recommendation
* CIS–CVSS advisor output
* CVSS score
* Response priority
* Recommended containment steps
* Final dashboard summary

---

## Sample Data

The repository includes sample data and pre-generated outputs for testing and demonstration.

These allow the dashboard and backend to work with sample incidents even before uploading new logs.

Sample data supports:

* Pipeline testing
* Dashboard preview
* Incident review
* Demo walkthroughs
* API validation

---

## Why This Matters for Banking SOCs

Banking environments are high-value targets and require fast, accurate incident response. SOC teams must quickly identify whether an event is benign, suspicious, or malicious, then determine impact, severity, and response priority.

This project demonstrates how layered automation can support analysts by:

* Reducing manual triage time
* Connecting related signals
* Providing consistent incident scoring
* Mapping detections to security controls
* Generating structured recommendations
* Improving incident visibility through a dashboard

---

## Future Improvements

Planned improvements could include:

* Real-time log streaming
* PostgreSQL database support
* Authentication and role-based access control
* SIEM integration
* EDR integration (automated host isolation rather than recommended isolation)
* Firewall automation (automated blocking rather than recommended blocking)
* Live threat intelligence feeds — the current feed is a local simulated file at
  `layer_2_detection/mappings/ioc_feed.json`
* Broader MITRE ATT&CK coverage — Layer 4 currently cites techniques for web
  attack classes only
* Analyst audit logs
* Docker-based deployment
* Cloud deployment support

### Known Limitations

Stated plainly, because they matter when reading the output:

* **Detection is rule-based, not machine-learned.** Anomaly scoring uses
  thresholds and field heuristics, not a trained model. This is a deliberate
  trade-off: every verdict is explainable and reproducible.
* **The IOC feed is simulated.** `layer_2_detection/mappings/ioc_feed.json` is a
  local file of demo indicators, not a live commercial feed.
* **Behavioural baselines are per-run.** There is no persistent user/host
  baseline across pipeline invocations, so "rare source IP" is judged within the
  batch being processed.
* **`layer_6_response/response_layer/` is a forward-looking design.** The live
  demo path is `layer_6_response/response_orchestrator.py`. The larger package
  (HITL approval, ticketing, playbook evolution) is unit-tested against mocks but
  is not wired into the pipeline and would need Elasticsearch, Redis and
  PostgreSQL to run for real.
* **`layer_3_cis/tuxSOC-layer_CIS/` is a vendored historical copy** of the CIS
  extraction work, kept for the benchmark catalogs it produced. Nothing on the
  live path imports it.

---

## Project Summary

**Cyber Incident Response in Banking SOC** is a full-stack cybersecurity project that demonstrates how raw security logs can be transformed into structured incident intelligence.

It combines:

* Backend APIs
* Multi-layer security analysis
* Detection engineering
* CIS benchmark mapping
* Agentic recommendation generation
* CVSS-style severity scoring
* Response recommendation
* Frontend visualization

The project is designed as a practical SOC simulation for banking incident response workflows.
