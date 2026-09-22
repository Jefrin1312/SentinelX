# SentinelX — Threat Model

Scope: SentinelX in its development architecture — a FastAPI backend, a
React SPA served by nginx, and PostgreSQL, deployed locally (Docker Compose)
or inside a company LAN. This document follows the classic
STRIDE-over-architecture approach: assets, trust boundaries, threats, and the
controls already implemented in the codebase.

## Assets

| # | Asset | Why it matters |
| -- | ----- | -------------- |
| A1 | `SECRET_KEY` | Signs every JWT; compromise = forge tokens |
| A2 | User password hashes | bcrypt hashes; breached = credential attack surface |
| A3 | **Security events** (incoming logs) | Untrusted attacker data; input to the pipeline |
| A4 | **Alerts, investigations, audit trail** | The SOC's integrity-sensitive findings and history |
| A5 | `DetectionRule` definitions | Tune detection behaviour; toggling rules can blind the SOC |
| A6 | Uploaded log files | Untrusted input, potential DoS / parser abuse vectors |
| A7 | API availability | Needed for SOC operations and monitoring |

## Trust boundaries

1. **Browser → nginx** — TLS terminates at the edge (assume reverse proxy in
   production). nginx sets `X-Forwarded-For` and hardening headers.
2. **nginx → backend** — internal network only.
3. **Backend → PostgreSQL** — private compose network, credentials via env.
4. **Untrusted log content → parser/normaliser** — an attacker controls bytes.
   This is the primary input boundary.
5. **Admin rules API → rule YAML on disk** — muxes between DB and `rules/`.

## Threats & controls

### T1 — Credential stuffing / brute force on login
- **Attack:** repeated login attempts against `/api/auth/login`.
- **Controls:** in-memory fixed-window rate limiter per client IP
  (`LOGIN_RATE_LIMIT`, default `10/minute`, replies `429`); bcrypt
  (`rounds=12`) makes each attempt expensive; every failed login is written to
  the immutable audit trail with IP; JWT `exp` bounds credential reuse.

### T2 — Stolen or forged tokens
- **Attack:** replay a captured JWT, or forge one after `SECRET_KEY` leaks.
- **Controls:** HS256 signed tokens; logout blacklists the `jti` in
  `token_blacklist`, checked on every protected request; tokens are short-lived
  (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 60); 401s clear the client token.
  Forged tokens fail signature verification before any DB access.

### T3 — Privilege escalation (analyst → admin)
- **Attack:** escalate role to reach admin-only endpoints.
- **Controls:** RBAC is **server-side**, enforced by FastAPI dependencies
  (`require_admin`/`require_analyst`) on every route. The role claim in the JWT
  is only a hint — the authoritative role is always reloaded from the DB.
  Registration always assigns `ANALYST`; the update guard refuses to disable or
  demote the last active admin.

### T4 — Injection into events / stored data
- **Attack:** submit crafted log lines or rule definitions to inject SQL,
  script or content into the SOC data.
- **Controls:** parser uses only declarative regex; input is never executed or
  interpolated. SQLAlchemy ORM parameterises all queries. The normaliser caps
  field lengths, coerces timestamps, and stores metadata as opaque JSON —
  malicious content can change values but never schema or query shape. nginx
  and FastAPI split authentication; the frontend renders data as text
  (React escape-by-default), and the API never returns the `password_hash`.

### T5 — Malicious/oversized uploads (parser DoS)
- **Attack:** upload huge files or engine-hostile content to exhaust memory.
- **Controls:** uploads bounded by `MAX_UPLOAD_SIZE_MB` (5 MB) and
  `MAX_UPLOAD_LINES` (5000) before parsing (413 rejected); per-batch
  `LogIngestBatch.lines` limited to 2000; invalid UTF-8 is replaced, never
  fatal; and the detection engine is deniable — a failing rule is logged and
  skipped so ingestion can never be blocked.

### T6 — Tampering or blinding the detection engine
- **Attack:** an insider or attacker toggles rules off to hide activity.
- **Controls:** rule enable/disable, create and reload are admin-only and every
  change (`RULE_CREATED`, `RULE_ENABLED/DISABLED`, `RULES_RELOADED`) is audited
  with actor and IP. Rule definitions are declarative data only.

### T7 — Loss of audit integrity / repudiation
- **Attack:** SOC actions unrecorded, or logs edited after the fact.
- **Controls:** every security-sensitive action (`LOGIN_*`, user/role changes,
  rule changes, alert transitions, investigations, `REPORT_GENERATED`,
  `LOGS_INGESTED`) is appended via `services.audit.write_audit` with actor,
  resource, IP and details; admin-only read/export. (Append-only in practice;
  consider a write-once store for a hardened deployment.)

### T8 — Mass data exfiltration
- **Attack:** reading every event/alert to map the defence network.
- **Controls:** analyst/admin auth required for reads; exports (alerts, events,
  audit) reuse the same filters and stay behind auth. Rate limiting throttles
  the one public, credential-independent attack surface (login).

### T9 — Dependency / supply-chain risk
- **Attack:** a compromised package in `requirements.txt` / `package.json`.
- **Controls:** pinned minimum versions, Docker images pinned by major version,
  minimal runtime (python:slim, nginx alpine), `npm audit` available in CI, and
  the backend runs as the container's default least-privilege user.

## Residual risks & notes

- **In-memory rate limiter** — per-process and lost on restart; adequate for a
  single-uvicorn deployment, but a multi-worker or multi-host setup should back
  it with shared storage (e.g. Redis). The `X-Forwarded-For` value is trusted
  from *our* nginx; if exposed directly, an attacker could forge the header.
- **JWT in localStorage** — a stored-XSS vector could read it. Mitigated by
  React's default escaping and CSP-friendly headers; a hardened deployment
  should use `HttpOnly` cookies.
- **No MFA** — acceptable for the demo scope; recommend TOTP/WebAuthn for real
  SOC use.
- **Demo seed credentials** — dev-only; they must be removed/disabled before
  real deployment (the bootstrap notes this).