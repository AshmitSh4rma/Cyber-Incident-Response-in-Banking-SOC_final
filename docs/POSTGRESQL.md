# PostgreSQL Setup and Migration

PostgreSQL is SENTRA's production persistence backend. SQLite remains available
only as a local development fallback when `ENVIRONMENT` is not `production` and
PostgreSQL has not been selected.

The database is accessed only by FastAPI:

```text
Browser -> Next.js -> FastAPI -> PostgreSQL
```

Never expose `DATABASE_URL` through `NEXT_PUBLIC_*` variables or frontend code.

## Local PostgreSQL setup

1. Create a PostgreSQL database.
2. Copy `.env.example` to `.env` and replace the placeholder values.
3. Load the variables into the current PowerShell session.
4. Install dependencies and apply migrations.
5. Start FastAPI.

```powershell
Copy-Item .env.example .env

# Edit .env, then load it into this PowerShell session:
Get-Content .env | ForEach-Object {
    if ($_ -match '^[^#][^=]*=') {
        $name, $value = $_ -split '=', 2
        Set-Item -Path "Env:$name" -Value $value
    }
}

python -m pip install -r requirements.txt
python -m database.migrate
python -m uvicorn api_server:app --reload --host 127.0.0.1 --port 8000
```

Verify connectivity without exposing database details:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok","database":"connected"}
```

## Hosted PostgreSQL (Neon, Render, or Railway)

Use the provider's pooled PostgreSQL URL where available. Both `postgres://` and
`postgresql://` schemes are accepted. SSL query parameters such as
`sslmode=require` and Neon connection options are preserved.

Configure these server-side backend variables:

```env
ENVIRONMENT=production
DB_BACKEND=postgresql
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=require
ALLOWED_ORIGINS=https://your-frontend.vercel.app
```

Apply migrations as a release step before starting a new backend version:

```powershell
python -m database.migrate
```

Suggested FastAPI host settings:

```text
Build command: pip install -r requirements.txt
Pre-deploy/release command: python -m database.migrate
Start command: uvicorn api_server:app --host 0.0.0.0 --port $PORT
```

The Vercel frontend receives only the public backend URL:

```env
NEXT_PUBLIC_SOC_API_URL=https://your-fastapi-backend.example.com
```

## Schema migrations

Numbered migrations live in `database/migrations/`. Applied versions and SHA-256
checksums are recorded in `schema_migrations`. An applied migration must never be
edited; create the next numbered file instead.

Apply pending migrations:

```powershell
python -m database.migrate
```

Application startup verifies the schema but does not create production tables.
If migrations are missing, startup fails with an actionable command.

## Migrate the existing SQLite data

Keep `soc_incidents.db` as a recovery source until validation is complete.
The importer opens SQLite read-only, upserts destination rows, preserves explicit
IDs and timestamps, and repairs PostgreSQL identity sequences. It never deletes
destination rows.

```powershell
python -m database.migrate
python -m scripts.migrate_sqlite_to_postgres --source .\soc_incidents.db
```

The utility prints only table row counts, never database credentials.

## Regenerate the demo data instead

When historic feedback and approvals are not required, initialize an empty
PostgreSQL database and rerun the deterministic scenario:

```powershell
python -m database.migrate
python dev_run.py
```

## PostgreSQL integration tests

The normal suite never needs production credentials. PostgreSQL tests run only
when `TEST_DATABASE_URL` is present. They create a unique temporary schema and
drop only that schema after the run.

```powershell
$env:TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST/TEST_DATABASE?sslmode=require'
python -m pytest tests/test_database_postgresql.py -q
```

Run the complete regression suite:

```powershell
python -m pytest -q
```

Do not set `TEST_DATABASE_URL` to a production database even though the tests are
schema-isolated.

## SQLite development fallback

For a no-service local demo only:

```powershell
$env:ENVIRONMENT='development'
$env:DB_BACKEND='sqlite'
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
python dev_run.py
```

Production explicitly rejects SQLite configuration.
