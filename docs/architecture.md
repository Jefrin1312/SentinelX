# SentinelX — Architecture

SentinelX is a full-stack SOC-style platform for ingesting security logs,
normalising them, detecting suspicious activity with a declarative rule engine,
and tracking alerts through an investigation workflow. This document describes
the system components and how data flows through the pipeline.

## Overview

```
                    ┌─────────────────────────────────────────────────┐
                    │                 Frontend (React)                 │
                    │  Dashboard / Logs / Alerts / Rules / Reports /   │
                    │  Investigations / Audit / Users / Settings       │
                    └───────────────┬─────────────────────────────────┘
                                    │ HTTP (JWT Bearer) /api/*
                    ┌───────────────▼─────────────────────────────────┐
                    │            Backend (FastAPI + SQLAlchemy)         │
                    │  auth ── logs ── dashboard ── alerts ── rules     │
                    │  investigations ── audit ── reports ── settings   │
                    │  │ detection engine    │ audit trail service      │
                    └───────────────┬─────────────────────────────────┘
                                    │ SQLAlchemy / psycopg
                    ┌───────────────▼─────────────────────────────────┐
                    │             PostgreSQL 16                         │
                    │  users events detection_rules alerts             │
                    │  investigations investigation_notes audit_logs   │
                    │  token_blacklist                                  │
                    └───────────────────────────────────────────────────┘
```

- **Frontend** — React 18 + Vite + Recharts. Single-page app served by nginx;
  nginx proxies `/api/*` to the backend. In local development the Vite dev
  server proxies `/api` to `http://localhost:8000`.
- **Backend** — FastAPI application with SQLAlchemy 2 ORM and Pydantic v2
  schemas. Exposes the REST API under the `/api` prefix and auto-generated
  OpenAPI docs at `/api/docs`.
- **Database** — PostgreSQL 16. The canonical schema is managed by SQLAlchemy
  (`backend/app/models`); `database/schema.sql` mirrors it for container
  bootstrap and as a human-readable reference.

## Application layout

```
backend/
  app/
    main.py                 # FastAPI app, CORS, router wiring, lifespan
    config.py               # Settings (env-driven, pydantic-settings)
    database.py             # SQLAlchemy engine / session
    bootstrap.py            # Startup: create tables + seed demo users + load rules
    api/                    # Routers: auth, users, dashboard, logs, alerts,
                            #   rules, investigations, audit, reports, settings, health
    auth/                   # security (JWT/bcrypt), dependencies, RBAC, rate limit
    logs/                   # parser → normaliser → collector pipeline
    detection/              # rule loader + threshold detection engine
    models/                 # ORM models
    schemas/                # Pydantic request/response models
    services/               # audit writer, CSV export, PDF report generation
rules/                      # Declarative detection rule bundles (YAML)
sample_logs/                # Bundled sample log files for the "import" feature
database/                   # schema.sql mirror + seed placeholder
frontend/src/
  pages/                    # One component per route
  components/               # Shared UI (StatCard, badges, tables, …)
  context/AuthContext.jsx   # JWT storage + auth state
  services/                 # Axios API modules
```

## Processing pipeline

```
 raw text ──► parse_log_line() ──► ParsedLog ──► normalize() ──► Event row
                (pure regex)         (dataclass)   (validate/cap)      │
                                                                      ▼
                                              detection engine ──► Alert rows
                                              (threshold rules)        │
                                                                      ▼
                                                             investigation workflow
```

### 1. Parsing (`app/logs/parser.py`)

A single raw log line is matched against declarative regular expressions and
turned into a structured `ParsedLog`. Input is always treated as data — it is
never executed or interpolated. Supported families:

| Family | Sources | Example event types |
| ------ | ------- | ------------------- |
| SSH | `auth.log`, `ssh.log` | `SSH_LOGIN_FAILURE`, `SSH_LOGIN_SUCCESS`, `AUTH_FAILURE` |
| System/auth | `auth.log` | `SUDO_COMMAND`, `USER_CREATED`, `USER_DELETED` |
| HTTP | `apache.log` (`nginx.log`) | `HTTP_REQUEST`, `HTTP_SUSPICIOUS_REQUEST` |

Web requests are additionally inspected for attack signatures
(`path_traversal`, `sql_injection`, `command_injection`, `xss_attempt`,
`encoded_payload`). A request carrying any signature is classified as
`HTTP_SUSPICIOUS_REQUEST` and stored with a `suspicious_signatures` metadata
list so the detection rules can trigger on it.

Lines that match nothing become `UNKNOWN` events — they are persisted, never
silently dropped.

### 2. Normalising (`app/logs/normalizer.py`)

The parsed record is validated and constrained before persistence: field
lengths are capped (IPs 45, usernames 100, messages 2000, …), empty strings
become `NULL`, timestamps are coerced to timezone-aware UTC, and metadata is a
plain JSON dict. Malformed content can change data values but never the schema
or the shape of a row.

### 3. Collecting (`app/logs/collector.py`)

`ingest_lines()` batches the pipeline: parse → normalise → persist each event →
run detection on it, then commits once per batch. Exact duplicate lines are
suppressed within a single *manual* ingest. The collector returns counters
(`parsed`, `unknown`, `events_created`, `alerts_created`, `event_ids`) used by
the API responses.

Three ingestion paths all feed this function:

- `POST /api/logs/ingest` — a JSON array of raw lines.
- `POST /api/logs/upload` — a text file (multipart), validated by size
  (`MAX_UPLOAD_SIZE_MB`, default 5 MB) and line count (`MAX_UPLOAD_LINES`,
  default 5000).
- `POST /api/logs/import` — a bundled file from `sample_logs/` by name.

### 4. Detecting (`app/detection/engine.py`)

Each stored event is evaluated against every **enabled** rule. Rules are purely
declarative and live in YAML bundles (`rules/*.yaml`), upserted into the
`detection_rules` table by name at startup (and reloadable on demand).

A rule matches when, inside its `time_window`:

- the event `event_type` matches (optionally `status`/`reason`/`signature`
  constraints),
- and the count of matching events for the grouping `key`
  (`source_ip` or `username`) reaches `threshold`.

Duplicate suppression: no second OPEN alert is raised for the same rule and
grouping value while an earlier OPEN alert from that rule is still live.
Detection is deniable — any rule error is logged and swallowed so a
misbehaving rule can never block ingestion.

## Auth: JWT + RBAC

- Passwords hashed with **bcrypt** (`rounds=12`) — never stored in plaintext.
- Login issues an **HMAC-SHA256 JWT** signed with `SECRET_KEY`, containing
  `sub`, `username`, `role`, `jti`, `iat`, `exp`. The `jti` lets logout revoke
  the token via the `token_blacklist` table.
- **Rate limiting**: `POST /api/auth/login` is throttled per client IP by an
  in-memory fixed-window limiter (`LOGIN_RATE_LIMIT`, default `10/minute`,
  returns `429`). The limiter honours `X-Forwarded-For` when present (as
  supplied by the nginx proxy).
- **RBAC** is enforced server-side on every request via FastAPI dependencies.
  The role inside the JWT is only a hint; the authoritative role is reloaded
  from the database each request.
  - `get_current_user` — any authenticated, active user.
  - `require_analyst` — SOC users (ANALYST and ADMIN).
  - `require_admin` — ADMIN only.

Self-registration always creates an `ANALYST` account; administrators exist
only via the seeded demo bootstrap.

## Audit trail

Every security-sensitive action is recorded through `services/audit.write_audit`
into `audit_logs` with the acting user, action constant, resource, client IP and
a JSON `details` blob. Recorded actions include `LOGIN_SUCCESS/_FAILURE`,
`LOGOUT`, `USER_CREATED`, role/enable changes, rule create/enable/disable/reload,
`ALERT_STATUS_CHANGED`, investigation create/update, `NOTE_ADDED`,
`REPORT_GENERATED`, and `LOGS_INGESTED`. The trail is queryable by admins and
exportable to CSV.

## Reports & dashboard

All figures are live SQL aggregations over the requested window — nothing is
hardcoded. The dashboard covers the last 24 hours; reports summarise events
and alerts with zero-filled daily time series, severity/status/type/source
breakdowns, top source IPs and event types, and average resolution time.
Reports download as JSON aggregates, CSV evidence (alerts/events/audit), or a
PDF security report (`services/pdf.py`, built with ReportLab from the same
live aggregates).

## Deployment

See `docs/installation.md`. Docker Compose runs three services — PostgreSQL,
FastAPI (uvicorn) and nginx-fronted React — with `rules/` and `sample_logs/`
mounted read-only into the backend container.