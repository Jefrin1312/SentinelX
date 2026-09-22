# SentinelX — Interview Walkthrough

Talking points and a demo script for presenting SentinelX as a full-stack
security project. Aim: show security thinking, engineering judgement, and the
ability to explain trade-offs — not just a list of features.

## Elevator pitch (30 seconds)

> "SentinelX is a full-stack SOC-style platform: it ingests raw security logs,
> normalises and parses them server-side, runs them through a declarative
> threshold-based detection engine to raise alerts, and supports an
> investigation workflow with notes, status transitions and a tamper-evident
> audit trail. The backend is FastAPI + SQLAlchemy on PostgreSQL; the frontend
> is React. Security is built in rather than bolted on — JWT auth with
> revocation, server-enforced RBAC, login rate limiting, and a full audit log."

## The three things I'd emphasise

1. **Security-first engineering.** Every log line is treated as untrusted data.
   The parser is pure regex (declarative, nothing executed), the normaliser
   constrains lengths/types so malformed input can't change the data shape, and
   SQLAlchemy parameterises all queries. Auth is real: bcrypt(12), short-lived
   HS256 JWTs with `jti` revocation on logout, rate-limited login, and RBAC
   re-checked from the DB on every request (never trusted from the token).

2. **A real data pipeline with a detection engine.** Show the boundary:
   *parse → normalise → persist → detect*. Detection rules are declarative YAML
   (`event_type` + grouping `key` + threshold over a time window), which makes
   them auditable, reloadable, and incapable of executing attacker input. I
   also decently handled duplicate suppression (no stacked OPEN alerts for the
   same rule + grouping value) and made detection "deniable" so a broken rule
   can never block ingestion.

3. **Defensible decisions + verification.** Everything is tested (117 tests,
   suite runs against a dedicated `sentinelx_test` DB), containerised
   (Compose + healthchecks), and versioned. I can explain *why* the rate
   limiter is in-memory and where it breaks down, why JWT-in-localStorage is
   acceptable here but why I'd move to HttpOnly cookies for production, and why
   the seed/demo credentials are dev-only.

## How it maps to the OSI/SOC mindset

- **Detection content** — rules are content: weighted threshold signals
  (SSH brute force, web attack signatures, sudo anomalous use), tunable,
  disableable, reload-able, fully audited.
- **Alert lifecycle** — `OPEN → INVESTIGATING → RESOLVED`, investigations with
  assignee + note thread, average time-to-resolve reported.
- **Evidence** — the audit trail and CSV exports give the SOC provable
  artefacts for sign-off (who did what, when, from which IP).
- **Reports** — live aggregates (daily time series, severity/status/source
  breakdowns), same fidelity as the dashboard, for a reviewable window.

## Demo script (2–3 minutes)

1. **Log in** as `admin / Admin@12345` (mention the seed is dev-only).
2. **Ingest** a sample: Logs → Import → `apache` (or `ssh`). Point out the
   response counters (`parsed`/`unknown`/`alerts_created`).
3. **Show the dashboard** — every number is a live SQL aggregate, not static.
4. **Open an alert**, transition it `OPEN → INVESTIGATING`, open an
   investigation, add a note.
5. **Audit tab** — replay what you just did; it's all there with actor/IP.
6. **Reports** — pick a window; the daily series and breakdowns are computed
   on the fly.
7. **Rules** — toggle a rule off/on (audited), or author a new one (persisted
   to `rules/*.yaml`).
8. **Export** an alert list / audit log to CSV as evidence.

## Questions you might expect (and short answers)

**"Why FastAPI?"**
Async-first, typed Pydantic request/response models (validation + OpenAPI docs
for free), and dependency injection that maps naturally onto auth/RBAC
dependencies.

**"How do you stop SQL injection / log injection?"**
ORM parameterisation everywhere; parser never executes input; normaliser caps
field lengths and forces timezone-aware types; metadata is a plain JSON dict.
Log lines can never change schema or query shape.

**"How secure is the login?"**
bcrypt(12) hashing, rate-limited endpoint (in-memory fixed-window, `429`
after the limit), audit of success/failure, revocable short-lived tokens.

**"Where's the boundary between analyst and admin?"**
Server-side dependencies (`require_analyst` / `require_admin`); the JWT role is
only a hint, the DB is the source of truth, and the last-admin guard prevents
locking yourself out.

**"What would you do differently for production?"**
Redis-backed rate limiting + trusted proxy networks; HttpOnly cookies / MFA;
the backend behind TLS at the edge; write-once/immutable audit storage;
`APP_ENV=production` with the demo seed disabled.

**"What's the best/most interesting part of the code?"**
The detection engine (`app/detection/engine.py`): declarative rule evaluation
over a rolling time window with duplicate suppression and deniable failures —
a small, testable core that drives the whole SOC workflow.

## Testimonial-style facts to cite

- 117 automated tests, run against an isolated `sentinelx_test` database.
- Two-env deploy story: Docker Compose for the demo, local dev via `uvicorn`
  + Vite proxy.
- Prefer boring, verifiable architecture: declarative rules, append-only audit
  trail, live aggregates over pre-computed dashboards.