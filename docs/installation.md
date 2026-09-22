# SentinelX — Installation & Configuration

## Prerequisites

- **Docker** with the Compose plugin (`docker compose version`) — for the
  one-command deployment.
- Alternative local development: **Python 3.11+**, **Node.js 18+** and a
  **PostgreSQL 14+** instance.
- Disk/ports: the compose stack publishes host ports `5432` (Postgres),
  `8000` (backend) and `8080` (frontend). Change `POSTGRES_PORT` to avoid
  conflicts.

## Quick start (Docker Compose)

```bash
cp .env.example .env    # optional — sane dev defaults exist
docker compose up --build
```

Then open:

- Frontend: http://localhost:8080
- Backend API docs (Swagger): http://localhost:8000/api/docs

The stack runs three services: `postgres` (16-alpine), `backend`
(Python 3.12 + uvicorn) and `frontend` (nginx serving the React build). The
backend mounts `rules/` and `sample_logs/` read-only, and waits for Postgres
health before starting. `rules/` and `sample_logs/` are mounted read-only so
the containers cannot modify repo files.

To stop: `docker compose down` — data stays in the `postgres_data` named
volume. To wipe it too: `docker compose down -v`.

## Demo accounts

On first startup the backend seeds two demo accounts (dev only):

| Role    | Username  | Password      |
| ------- | --------- | ------------- |
| Admin   | `admin`   | `Admin@12345` |
| Analyst | `analyst` | `Analyst@12345` |

Self-registration always creates an `ANALYST` account (10+ character
password). The seed only runs from `backend/app/bootstrap.py` and can be
disabled in production by not running that path (see below).

## Configuration

Copy `.env.example` to `.env`. All settings are read from the environment by
the backend (`app/config.py`, pydantic-settings). Documented values:

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `POSTGRES_USER` | `sentinelx` | Postgres user (compose) |
| `POSTGRES_PASSWORD` | `change_me` | Postgres password (compose, dev only) |
| `POSTGRES_DB` | `sentinelx` | Database name (compose) |
| `POSTGRES_PORT` | `5432` | Host port for Postgres |
| `DATABASE_URL` | local URL | SQLAlchemy connection string (`postgresql+psycopg://…`) |
| `SECRET_KEY` | `change-me-in-production` | HMAC-SHA256 JWT signing secret — **must** be replaced in any shared deployment |
| `CORS_ORIGINS` | `http://localhost:5173,…` | Comma-separated allowed browser origins |
| `APP_ENV` | `development` | Environment label; `production` recommended in prod |
| `DEBUG` | `false` | Enable verbose debug behaviour |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT lifetime in minutes |
| `LOGIN_RATE_LIMIT` | `10/minute` | Login brute-force limit per IP; `0/minute` or empty disables |
| `MAX_UPLOAD_SIZE_MB` | `5` | Max uploaded log file size |
| `MAX_UPLOAD_LINES` | `5000` | Max uploaded log lines |
| `VITE_API_TARGET` | `http://localhost:8000` | Backend URL for the Vite dev proxy |

The compose file injects `DATABASE_URL`, `SECRET_KEY`, `CORS_ORIGINS` and
`APP_ENV` into the backend container, wiring Postgres through the compose
network (host `postgres`, port `5432`).

## Local development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Point at a local Postgres and run:
export DATABASE_URL="postgresql+psycopg://sentinelx:secret@127.0.0.1:5432/sentinelx"
uvicorn app.main:app --reload --port 8000
```

On startup the app creates tables and seeds demo users
(`app/bootstrap.init_db()`), so no manual migration step is needed. The
OpenAPI docs are at http://localhost:8000/api/docs.

### Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to the backend
```

Production build: `npm run build` (outputs to `frontend/dist`).

## Running the tests

The test suite runs against a dedicated `sentinelx_test` database so it never
touches development data. It expects a PostgreSQL reachable at
`127.0.0.1:5432` with the credentials baked into `backend/tests/conftest.py`
(run `docker run` or an existing container as Postgres 16):

```bash
cd backend
.venv/bin/python -m pytest -q
```

`conftest.py` drops and recreates the schema once per session, disables login
rate limiting (the suite shares one TestClient IP), and provides `client`,
`db`, `auth_headers` and `admin_headers` fixtures.

## Rules & sample data

- **Detection rules** live in `rules/*.yaml` (see `rules/README.md`). The
  backend upserts them by name at startup; admins can also author rules via the
  API/UI (written back to the YAML bundles) or reload them from disk
  (`POST /api/rules/reload`).
- **Sample logs** live in `sample_logs/` (`ssh.log`, `apache.log`,
  `nginx.log`, `auth.log`). They contain only simulated events and are for
  local, authorised demonstration. Import them from the Logs page or
  `POST /api/logs/import?sample=<name>`.

## Database schema

The canonical schema is managed by SQLAlchemy (`backend/app/models`).
`database/schema.sql` mirrors it and is executed on first Postgres startup by
`docker-entrypoint-initdb.d` for convenience and readability, and
`database/seed.sql` documents the runtime seed (the real seed runs from the
backend bootstrap so it stays in sync with hashing settings).

## Troubleshooting

- **Port already in use** — change `POSTGRES_PORT` in `.env`, or the backend
  `8000`/frontend `8080` mappings in `docker-compose.yml`.
- **Login rate limited during demos/tests** — set `LOGIN_RATE_LIMIT=0/minute`.
- **Nothing appears on the dashboard** — ingest a sample log (`ssh`, `apache`,
  `auth`) from the Logs page.
- **CORS errors in the browser** — include the exact origin (with port) in
  `CORS_ORIGINS`.