# SENTRA: Project Architecture and PostgreSQL Migration Guide

## 1. Project Overview

SENTRA is a full-stack Security Operations Center (SOC) incident-response platform designed for banking-style security operations.

The project accepts raw security logs and turns them into structured, explainable incidents. It detects suspicious activity, correlates related alerts into attack campaigns, maps activity to MITRE ATT&CK and CIS controls, calculates CVSS severity, recommends containment actions, requests human approval for disruptive actions, and produces audit-ready reports.

The primary product story is:

```text
Raw security telemetry
  -> Normalized security events
  -> Threat and anomaly detection
  -> Correlated attack campaign
  -> MITRE ATT&CK and CIS mapping
  -> AI-assisted analysis
  -> CVSS risk score
  -> Human-approved response plan
  -> Audit evidence
```

SENTRA is a defensive security prototype and decision-support system. It recommends and records response actions; it is not currently connected to production firewalls, identity providers, or endpoint tools.

## 2. Technology Stack

### Backend

- Python 3
- FastAPI
- Uvicorn
- Pydantic
- PostgreSQL in production through Psycopg 3 and a bounded connection pool
- Optional SQLite fallback for local development
- LangGraph and optional Ollama integration
- Pytest

### Frontend

- Next.js 16 App Router
- React 19
- TypeScript
- Tailwind CSS
- Framer Motion
- Lucide icons

### Security analysis

- Rule-based and heuristic feature extraction
- Threat-pattern detection
- IOC enrichment
- Cross-signal correlation
- MITRE ATT&CK mapping
- CIS benchmark retrieval
- CVSS 3.1-style scoring
- Response playbook generation
- Human-in-the-loop approval records

## 3. Runtime Architecture

```text
Browser
  |
  v
Next.js frontend and API proxy routes
  |
  v
FastAPI backend
  |
  +-> SOC analysis pipeline
  |
  +-> Incident, campaign, feedback and approval APIs
  |
  +-> Audit-report generation
  |
  v
Hosted PostgreSQL in production / optional SQLite local fallback
```

The frontend does not access the database directly. It calls Next.js route handlers, which proxy requests to FastAPI. FastAPI owns the pipeline and persistence layer.

## 4. Processing Pipeline

The canonical pipeline is defined in `pipeline.py`.

### Layer 1: Ingestion and feature engineering

Location: `layer_1_feature_engineering/`

Responsibilities:

- Parse JSON and JSONL input.
- Normalize inconsistent source fields.
- Classify log families.
- Extract temporal features.
- Build behavioral profiles.
- Detect statistical patterns.
- Analyze network and protocol activity.
- Analyze HTTP and session behavior.
- Analyze IoT telemetry.
- Extract identity-related signals.
- Produce a detection-ready event structure.

### Layer 2: Detection

Location: `layer_2_detection/`

Responsibilities:

- Evaluate anomaly rules.
- Score suspicious behavior.
- Match known threat patterns.
- Extract observables.
- Compare observables with the local IOC feed.
- Correlate signals from multiple detection engines.
- Apply analyst-created suppression rules.
- Fuse the results into a final verdict, severity and confidence score.

### Layer 2.5: Campaign correlation and ATT&CK mapping

Important files:

- `layer_2_detection/mitre_mapper.py`
- `layer_2_detection/campaign_correlator.py`

Responsibilities:

- Map detections to MITRE ATT&CK techniques and tactics.
- Assign a kill-chain stage.
- Link incidents using shared actors, accounts and assets.
- Build deterministic multi-stage attack campaigns.
- Escalate campaign severity when progression warrants it.

Campaign correlation runs after frontend formatting because it depends on stable incident IDs.

### Layer 3: CIS control mapping

Location: `layer_3_cis/`

Responsibilities:

- Route incidents to network, web or IoT control engines.
- Search the bundled benchmark catalogs.
- Return applicable CIS or OWASP controls.
- Include rationale, remediation and audit procedures.

### Layer 4: AI-assisted analysis

Location: `layer_4_ai_analysis/`

Responsibilities:

- Explain assessed attacker intent.
- Produce a security narrative.
- Suggest impact and exploitability context.
- Provide structured input to the CVSS layer.

If a compatible local Ollama model is unavailable, the system uses a deterministic rule-based fallback. The pipeline is therefore usable without an external LLM.

### Layer 5: CVSS scoring

Location: `layer_5_cvss/`

Responsibilities:

- Map exploitability metrics.
- Map confidentiality, integrity and availability impact.
- Validate and apply fallbacks.
- Calculate a base score.
- Produce a severity label and CVSS vector.

### Layer 6: Response recommendation

Location: `layer_6_response/`

Responsibilities:

- Determine response priority.
- Generate recommended actions.
- Build a structured containment plan.
- Mark disruptive actions as requiring analyst approval.
- Generate escalation guidance.

The current implementation records approvals but does not execute actions against real EDR, IAM, firewall or ticketing systems.

## 5. Repository Structure

```text
Cyber-Incident-Response-in-Banking-SOC_final/
|
|-- Frontend/                         Next.js application
|   |-- app/                          Pages and server-side proxy routes
|   |   |-- api/                      Proxies to the FastAPI backend
|   |   |-- campaigns/                Campaign list and detail pages
|   |   |-- dashboard/                Primary incident dashboard
|   |   |-- incident/[id]/            Incident workspaces
|   |   `-- upload/                   Simulation and log-upload interface
|   |-- components/                   UI cards, layouts and visuals
|   |-- hooks/                        Client-side React hooks
|   |-- lib/                          Types, adapters, mock data and API helpers
|   `-- public/                       Static demo artifacts
|
|-- layer_1_feature_engineering/      Parsing, normalization and features
|-- layer_2_detection/                Detection, IOC, ATT&CK and campaigns
|-- layer_3_cis/                      CIS and OWASP control mapping
|-- layer_4_ai_analysis/              Ollama analysis and deterministic fallback
|-- layer_5_cvss/                     CVSS metric mapping and scoring
|-- layer_6_response/                 Response and containment recommendations
|-- tests/                            Cross-layer regression tests
|
|-- api_server.py                     Canonical FastAPI application
|-- pipeline.py                       Canonical end-to-end pipeline sequence
|-- db_config.py                      Environment-driven database configuration
|-- database/                         Pool lifecycle and PostgreSQL migrations
|-- db_manager.py                     Shared PostgreSQL/SQLite persistence API
|-- frontend_formatter.py             Dashboard data-contract formatter
|-- audit_report.py                   Incident and campaign Markdown reports
|-- soc_metrics.py                    Computed SOC performance metrics
|-- dev_run.py                        Offline pipeline and demo-data runner
|-- view_db.py                        Configured-database inspection utility
|-- requirements.txt                  Python dependencies
|-- pytest.ini                        Python test configuration
|-- soc_incidents.db                  Current local demo database
|-- demo_attack_scenario.json         Main hackathon demo scenario
`-- README.md                         Public project introduction
```

## 6. Major Backend APIs

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/run-pipeline` | Process an uploaded JSON or JSONL log file |
| `GET` | `/api/incidents` | List stored incidents |
| `GET` | `/api/incidents/{id}` | Retrieve one incident |
| `POST` | `/api/incidents/{id}/action` | Update incident status |
| `DELETE` | `/api/incidents` | Clear incidents and campaigns |
| `GET` | `/api/campaigns` | List correlated campaigns |
| `GET` | `/api/campaigns/{id}` | Retrieve a campaign and its incidents |
| `GET` | `/api/metrics` | Retrieve computed SOC metrics |
| `POST` | `/api/incidents/{id}/feedback` | Record analyst feedback |
| `GET` | `/api/suppression-rules` | List learned suppression rules |
| `GET` | `/api/approvals` | List response approvals |
| `POST` | `/api/incidents/{id}/approvals` | Request action approval |
| `POST` | `/api/approvals/{id}/decision` | Approve or reject an action |
| `GET` | `/api/incidents/{id}/report` | Download an incident audit report |
| `GET` | `/api/campaigns/{id}/report` | Download a campaign audit report |

## 7. Current Database

The project now uses PostgreSQL as its required production backend. `db_manager.py`
obtains managed PostgreSQL connections from a bounded Psycopg pool. The
repository-local `soc_incidents.db` remains only as a recovery source and an
optional development fallback.

It stores four major entities:

- Incidents
- Analyst feedback
- Correlated campaigns
- Response approvals

SQLite is suitable for a single-machine demonstration, but production explicitly
rejects it because separate backend instances would have separate files and many
cloud platforms use ephemeral filesystems.

## 8. Target Hosted Architecture

The recommended hackathon deployment is:

```text
Next.js frontend: Vercel
FastAPI backend: Render or Railway
PostgreSQL database: Neon
```

The FastAPI backend should be the only component that receives the database connection string. The browser and Next.js client must never receive database credentials.

# PostgreSQL Migration and Deployment Plan

The implementation described below is present in the repository. Operational
phases that require hosted credentials must be completed per environment. Exact
commands are maintained in `docs/POSTGRESQL.md`.

## Phase 0: Decisions and safety baseline

### Objective

Freeze the database contract and establish a recovery point before changing persistence.

### Tasks

1. Back up `soc_incidents.db`.
2. Record row counts for every SQLite table.
3. Confirm whether existing data must be preserved or demo data can be regenerated.
4. Choose the hosted services:
   - Neon for PostgreSQL.
   - Render or Railway for FastAPI.
   - Vercel for Next.js.
5. Decide on separate development and production databases.
6. Run the existing test suite and save the result as the baseline.

### Exit criteria

- A recoverable SQLite backup exists.
- The current tests pass.
- Hosting providers and environments are selected.
- The data-preservation decision is documented.

## Phase 1: Provision PostgreSQL

### Objective

Create an empty hosted PostgreSQL database without changing application behavior.

### Tasks

1. Create a Neon project.
2. Create or identify development and production database branches.
3. Copy the pooled PostgreSQL connection string.
4. Store it locally in an ignored `.env` file:

   ```env
   DATABASE_URL=postgresql://user:password@host/database?sslmode=require
   ```

5. Verify the connection with a minimal read-only query.
6. Do not place the connection string in frontend code or any `NEXT_PUBLIC_*` variable.

### Exit criteria

- PostgreSQL accepts an SSL connection from the development machine.
- Credentials are not tracked by Git.
- Development and production environments are separated.

## Phase 2: Introduce database configuration

### Objective

Make database selection environment-driven instead of hard-coded to SQLite.

### Tasks

1. Add Psycopg 3 to `requirements.txt`:

   ```text
   psycopg[binary]>=3.2,<4
   ```

2. Read `DATABASE_URL` from the environment.
3. Fail at startup with a clear message when production has no database URL.
4. Optionally preserve SQLite fallback for local development only.
5. Never log the connection string.

### Recommended configuration contract

```text
DATABASE_URL     PostgreSQL connection string
DB_BACKEND       Optional explicit backend selector
ENVIRONMENT      development, test or production
```

### Exit criteria

- The backend can connect using environment configuration.
- Secrets do not appear in logs or responses.
- Local and hosted configurations are documented.

## Phase 3: Create versioned PostgreSQL schema migrations

### Objective

Replace SQLite runtime schema creation and `PRAGMA` migrations with repeatable PostgreSQL migrations.

### Tasks

1. Introduce a migration tool such as Alembic, or maintain numbered SQL migrations.
2. Create tables for:
   - `incidents`
   - `analyst_feedback`
   - `campaigns`
   - `response_approvals`
3. Replace SQLite `AUTOINCREMENT` with PostgreSQL identity columns.
4. Add foreign keys from feedback and approvals to incidents.
5. Add `ON DELETE CASCADE` where deletion should remove dependent records.
6. Add indexes for frequently filtered fields:
   - Incident timestamp
   - Severity
   - Status
   - Campaign progression
   - Approval state
7. Initially retain pipeline payloads as `TEXT` for compatibility, or deliberately migrate them to `JSONB` with corresponding code changes.
8. Add check constraints for known approval and incident states.

### Exit criteria

- A new empty database can be created using migrations alone.
- Running migrations twice is safe.
- Foreign keys prevent orphaned records.
- Indexes exist for primary dashboard queries.

## Phase 4: Port the persistence layer

### Objective

Make every function in `db_manager.py` work with PostgreSQL.

### Tasks

1. Replace `sqlite3.connect()` with `psycopg.connect()`.
2. Configure dictionary-style result rows.
3. Change SQLite `?` placeholders to Psycopg `%s` placeholders.
4. Remove `PRAGMA` usage.
5. Verify `ON CONFLICT` statements against PostgreSQL.
6. Use context managers so failed operations roll back and connections close.
7. Make complete pipeline persistence transactional:
   - Save incidents.
   - Replace campaigns.
   - Commit only after all database writes succeed.
8. Keep JSON serialization behavior consistent.
9. Add bounded connection pooling before production deployment.

### Exit criteria

- All existing persistence functions work against PostgreSQL.
- A failed write rolls back the complete operation.
- Connections are always returned or closed.
- No SQLite-only SQL remains on the production path.

## Phase 5: Migrate or regenerate data

### Option A: Regenerate demo data

This is recommended for the hackathon when historical analyst activity is not important.

1. Apply the PostgreSQL schema migrations.
2. Point the backend at the development database.
3. Run `python dev_run.py`.
4. Confirm incidents and campaigns appear in PostgreSQL.

### Option B: Preserve the SQLite database

1. Write a one-time migration utility.
2. Read every SQLite table in dependency order.
3. Insert incidents first.
4. Insert campaigns, feedback and approvals.
5. Preserve IDs and timestamps.
6. Reset PostgreSQL identity sequences.
7. Compare source and destination row counts.
8. Sample payloads and verify JSON integrity.
9. Retain the SQLite file as a read-only backup until validation is complete.

### Exit criteria

- Expected records exist in PostgreSQL.
- Foreign-key relationships are valid.
- Row counts and sampled payloads match.
- The application can read migrated data.

## Phase 6: Database integration tests

### Objective

Prove that behavior is preserved before deployment.

### Required tests

- Initialize a clean test database.
- Save and retrieve an incident.
- Update incident status.
- Upsert the same incident.
- Save and retrieve feedback.
- Generate and retrieve suppression rules.
- Replace and retrieve campaigns.
- Request and decide an approval.
- Reject a second decision on an already decided approval.
- Delete an incident and verify dependent records cascade.
- Roll back a deliberately failed pipeline write.
- Run two concurrent updates without corrupting state.

### Exit criteria

- Unit and integration tests pass.
- Tests run against an isolated database.
- Production credentials are never used by tests.

## Phase 7: Deploy the FastAPI backend

### Objective

Host the API with durable access to PostgreSQL.

### Render-style configuration

```text
Runtime: Python
Build command: pip install -r requirements.txt
Start command: uvicorn api_server:app --host 0.0.0.0 --port $PORT
```

### Backend environment variables

```env
DATABASE_URL=<Neon pooled connection string>
ENVIRONMENT=production
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

### Tasks

1. Connect the Git repository to the backend host.
2. Configure secrets in the provider dashboard.
3. Run migrations during release or before the first deployment.
4. Deploy FastAPI.
5. Verify the root and health endpoints.
6. Upload a small test scenario.
7. Verify records appear in PostgreSQL.
8. Configure logs and service health checks.

### Exit criteria

- The hosted API responds over HTTPS.
- The API reads and writes PostgreSQL.
- Restarting the service does not lose data.
- Database credentials are absent from build logs and responses.

## Phase 8: Deploy and connect the frontend

### Objective

Point the deployed Next.js application to the hosted FastAPI backend.

### Vercel configuration

Set the `Frontend` directory as the project root and configure:

```env
NEXT_PUBLIC_SOC_API_URL=https://your-fastapi-service.example.com
```

This variable contains the public backend URL, not the database URL.

### Tasks

1. Deploy the `Frontend` directory to Vercel.
2. Configure the backend URL for development, preview and production.
3. Redeploy after changing environment variables.
4. Restrict FastAPI CORS to the deployed frontend origins.
5. Test every frontend proxy route.

### Exit criteria

- The dashboard loads hosted incidents.
- Uploads reach the hosted pipeline.
- Campaign, approval, feedback and report routes work.
- Browser requests do not encounter CORS errors.

## Phase 9: Security hardening

### Objective

Protect the hosted SOC data and destructive operations.

### Tasks

1. Add authentication.
2. Add analyst and administrator roles.
3. Derive `decided_by` from the authenticated identity rather than request input.
4. Restrict deletion, suppression and approval decisions by role.
5. Restrict CORS to known frontend origins.
6. Rotate any credential exposed during development.
7. Require SSL for PostgreSQL.
8. Configure database backups or point-in-time recovery.
9. Add rate limiting to upload and mutation endpoints.
10. Set request-size and processing-time limits.
11. Sanitize downloadable report fields.
12. Record immutable audit events for critical state changes.

### Exit criteria

- Anonymous callers cannot read or modify SOC data.
- Analyst actions are attributable to authenticated users.
- Database recovery is documented and tested.

## Phase 10: Cutover and cleanup

### Objective

Make PostgreSQL the only production persistence path and remove misleading runtime artifacts.

### Tasks

1. Run the final migration or demo seed.
2. Temporarily stop writes during the cutover if real data must be preserved.
3. Switch the production `DATABASE_URL`.
4. Run smoke tests.
5. Compare incident and campaign counts.
6. Retain the SQLite backup for an agreed rollback period.
7. Remove `soc_incidents.db` from Git tracking.
8. Add runtime databases and generated output to `.gitignore`.
9. Keep sanitized fixtures in a dedicated test or demo directory.
10. Document rollback steps.

### Exit criteria

- Production uses PostgreSQL exclusively.
- No production data depends on the application filesystem.
- A rollback path exists.
- The repository contains fixtures, not live runtime state.

## Phase 11: Post-deployment validation

Run this complete demonstration flow:

1. Open the hosted dashboard.
2. Run the demo attack scenario.
3. Confirm incidents are created.
4. Confirm related incidents form a campaign.
5. Inspect MITRE ATT&CK and CIS mappings.
6. Confirm CVSS and containment results.
7. Request and decide a response approval.
8. Submit analyst feedback.
9. Restart the backend.
10. Confirm all data remains available.
11. Download incident and campaign reports.
12. Review backend and database logs for errors.

## 9. Suggested Environment Matrix

| Environment | Frontend | Backend | Database |
| --- | --- | --- | --- |
| Local | Next.js dev server | Local Uvicorn | Local Postgres or SQLite fallback |
| Preview | Vercel preview | Staging backend | Neon development/preview branch |
| Production | Vercel production | Production backend | Neon production branch |

Never allow preview deployments to write into the production database.

## 10. Verification Commands

Backend tests:

```powershell
python -m pytest -q
```

Backend development server:

```powershell
python -m uvicorn api_server:app --reload --host 127.0.0.1 --port 8000
```

Frontend checks:

```powershell
cd Frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run dev
```

Offline demo pipeline:

```powershell
python dev_run.py
```

## 11. Final Definition of Done

The PostgreSQL migration is complete only when:

- The schema is created by versioned migrations.
- FastAPI uses `DATABASE_URL` and PostgreSQL in production.
- Existing or regenerated demo data is present.
- All database integration tests pass.
- Pipeline writes are atomic.
- Foreign keys prevent orphaned feedback and approvals.
- The hosted frontend reaches the hosted backend.
- Restarting or redeploying the backend does not lose data.
- Database credentials are server-only and absent from Git.
- Authentication protects SOC data and mutation endpoints.
- SQLite is retained only as an optional local-development fallback or archived backup.
