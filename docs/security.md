# SentinelX — Security documentation

This document describes the security controls **actually implemented** in SentinelX as of the 0.4.x series. It deliberately does not claim protections that do not exist; where a control is development-grade or has a known limitation, that is stated explicitly. Related reading: [architecture](architecture.md), [threat model](threat-model.md), [install/run](installation.md).

---

## 1. Authentication architecture

Authentication is bearer-token based (RFC 6750 style). Every protected endpoint requires an `Authorization: Bearer <jwt>` header, parsed by `app/auth/dependencies.py`.

| Concern | Implementation |
|---|---|
| Account creation | `POST /api/auth/register` — self-registration **always** creates an `ANALYST` account. |
| Login | `POST /api/auth/login` — verifies the bcrypt hash, issues a JWT, records `LOGIN_SUCCESS`/`LOGIN_FAILURE` in the audit log. Failed logins additionally count towards the rate limiter. |
| Logout | `POST /api/auth/logout` — adds the token's `jti` to the `token_blacklist` table and returns `204`, so the token can no longer be used. |

The authenticated identity is re-derived from the database **on every request** (`app/auth/dependencies.py._current_user`); a JWT is invalidated immediately if the user is disabled or deleted.

## 2. Password hashing

- Passwords are hashed with **bcrypt** (`app/auth/security.py.hash_password`) using cost factor **12** (`bcrypt.gensalt(rounds=12)`).
- The salt is embedded in the hash; only the hash is stored (`users.password_hash`). It is **never** returned by any API response (`UserOut` in `app/schemas/auth.py` omits it).
- Passwords are limited to a maximum of **72** bytes (bcrypt's input ceiling) and a minimum of 10 characters via Pydantic validation.
- `verify_password` swallows malformed-hash `ValueError`s and returns `False` rather than raising.

## 3. JWT authentication

- Tokens are **HMAC-SHA256** signed (`HS256`) using `JWT_SECRET`/`SECRET_KEY` from the environment (`app/auth/security.py`).
- Claims: `sub` (user id), `username`, `role` (convenience hint only — never authoritative), `jti` (unique id), `iat`, `exp`.
- Decoding uses `PyJWT` with an explicit allowed-algorithm whitelist `[HS256]` (algorithms are never taken from the token header), and the selected algorithm comes from settings.

## 4. JWT expiration and revocation

- **Expiration:** default `ACCESS_TOKEN_EXPIRE_MINUTES=60`. Expired tokens get a distinct `401 "Token has expired."`.
- **Revocation:** on logout the `jti` is persisted in `token_blacklist`; `_current_user` rejects any token whose `jti` is present, with `401 "Token has been revoked."`.
- **Limitation (documented):** blacklist entries are never purged automatically. They accumulate until the administrator resets the database or the table is cleaned manually. In typical single-deployment SOC use this is negligible; a production enhancement would be a sweep job or Redis-backed blacklist with TTL.
- `TokenBlacklist.jti` is unique + indexed, so lookups are O(1) on an index.

## 5. Role-based access control

- Two roles: `ADMIN` and `ANALYST` (`app/models/user.py.UserRole`).
- Self-registration only ever produces `ANALYST`. `ADMIN` accounts can only be created by an existing admin changing a role, or via the seeded demo / bootstrap data.
- Guards live at the **route dependency** layer, so they cannot be bypassed from the frontend:
  - `require_analyst` — any active analyst **or** admin (reports, dashboard, ingestion, alerts, rules view).
  - `require_admin` — settings, user management, audit-log viewing (see `app/auth/authorization.py`).
- The role in the JWT is a hint; enforcement reads the role from the live `users` row.

## 6. Backend authorization

- Every protected endpoint declares its dependency explicitly (`CurrentUser`, `require_analyst`, `require_admin`, `AdminUser`).
- Tracked in the codebase: `/users`, `/settings`, `/audit-logs` (and their exports) are admin-only; everything else SOC-facing requires an analyst.
- Self-protection: an admin **cannot** disable or demote themselves when they are the last active administrator (`app/api/users.py:82`).
- All role/active changes to users are audit-logged (`USER_ROLE_CHANGED`, `USER_DISABLED`, `USER_ENABLED`).

## 7. Input validation

- **API layer (Pydantic):** every request body and query parameter is validated, e.g.:
  - `username`: `^[a-zA-Z0-9_\-\.]+$`, 3–50 chars.
  - `email`: validated as a real email address (`EmailStr`).
  - `password`: 10–72 chars on register/change.
  - Query parameters carry `ge`/`le`/`max_length` bounds (e.g. `days` 1–90, `limit` 1–500, `topn` 1–25) so extreme values are rejected before touching the database.
- **Log pipeline layer:** the normaliser (`app/logs/normalizer.py`) strips, null-ifies empties, and **caps every field length** (`message` ≤ 2000, `source_ip` ≤ 45, `username` ≤ 100, …). Untrusted log content can produce events, never schema or shape changes.

## 8. SQL injection prevention

- All persistence and querying goes through the **SQLAlchemy ORM expression API**; values are bound parameters, never interpolated strings. Search filters use `ilike(bound_param)`.
- No raw SQL strings with external input were found in the application layer.
- The only raw SQL constructs are fixed expressions used for time bucketing (`func.date_trunc`, `func.extract`) with constant arguments.

## 9. XSS protection

- The frontend is **React**; by default React escapes interpolated values before rendering. A repository scan found no `dangerouslySetInnerHTML`, `eval`, or `document.write` in `frontend/src`.
- Log lines, usernames, alerts, and rule text are all rendered as text nodes, not injected HTML.
- Persisted content is treated as data at render time (defense in depth on top of escaping).
- **Limitation (documented):** there is no `Content-Security-Policy` header (see §12). This is acceptable for a lab platform but should be addressed before Internet-facing deployment; see the production recommendations.

## 10. CORS configuration

- Configured via `CORS_ORIGINS` (comma-separated env var), parsed into an explicit allowlist in `app/config.py` and applied with `CORSMiddleware` in `app/main.py`.
- `allow_credentials=True`; methods and headers are permissive, but **origin is allowlisted** — a browser on an unknown origin cannot read API responses.
- Default dev origins are the Vite dev server (`localhost:5173`); compose sets `http://localhost:8080`.

## 11. Rate limiting

- `POST /api/auth/login` is limited by an **in-memory fixed-window** limiter keyed on client IP (`app/auth/ratelimit.py`).
- Default: `LOGIN_RATE_LIMIT=10/minute`; syntax `N/second|minute|hour`; `0` disables (used by the test suite).
- Exceeded attempts return `429 Too Many Requests`; the correct `Retry-After`-style signal is the `detail` message.
- **Limitations (documented):**
  - Per-process in-memory state: it only counts requests served by the **same uvicorn worker/process**. Multi-worker or multi-replica deployments need a shared store (Redis) for a global limit.
  - Keyed on the immediate client IP. Behind a reverse proxy the app reads `X-Forwarded-For` only where implemented, so a proxy must be trusted or the key should be the proxy's client IP.

## 12. Security headers

Set by the nginx server block (`frontend/nginx.conf`) on all responses:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

To be accurate: there is currently **no** HSTS and **no** Content-Security-Policy header. HSTS requires HTTPS termination (see production recommendations); a CSP has not been written because the app's inline-styles-heavy UI would need tuning first. These are open hardening items, not claims.

## 13. Secure file upload handling

- Uploads go through `POST /api/logs/upload` and are treated as **opaque text data** — nothing is executed, stored on disk, or served back as a resource.
- **Size validation:** the body is capped at `MAX_UPLOAD_SIZE_MB` (default 5 MB) → `413` on excess (`_validate_bytes`).
- **Line validation:** at most `MAX_UPLOAD_LINES` (default 5000) lines are accepted.
- **Encoding:** decoded as UTF-8 with `errors="replace"`, so malformed bytes cannot crash parsing.
- **Path traversal protection / filename safety:** the uploaded filename is reduced to its basename and truncated (`_sanitise_filename`), and is never used for filesystem access. The bundled-sample importer only accepts an allowlisted set `{ssh, apache, nginx, auth}` and resolves within fixed sample directories, so `../` style traversal is impossible.

## 14. File size/type validation

- Covered in §13: size caps (bytes and lines) plus UTF-8-with-replacement decoding. The accepted "type" is plain text; there is no magic-byte sniffing because the file is never treated as anything other than text.

## 15. Path traversal protection

- Sample-log import: allowlist + path confinement (§13).
- No endpoint writes user-controlled paths; exports generate filenames server-side (e.g. `sentinelx_report_…pdf`, `alerts.csv`).

## 16. Error handling

- A global exception handler in `app/main.py` returns `500 {"detail": "An internal server error occurred."}` — **no stack traces, exception types, or internal paths leak to clients.**
- Auth failures use explicit, distinct `401` messages (expired / revoked / invalid / inactive) with correct `WWW-Authenticate` headers.
- Pydantic validation errors return structured `422` detail lists (validation messages only).
- Known-absence responses use `404` with a plain message (e.g. unknown sample file).

## 17. Secrets management

- All secrets and credentials come from the environment via `pydantic-settings` (`app/config.py`): `SECRET_KEY`, `DATABASE_URL` (embeds the DB password), `JWT_ALGORITHM`, `CORS_ORIGINS`.
- `.env` files are git-ignored; only `.env.example` with **development-only** placeholder values is committed.
- Demo credentials (`admin` / `Admin@12345`, `analyst` / `Analyst@12345`) are seeded by `bootstrap.py` and clearly labelled as dev-only in the README and docs.
- **Limitation (documented):** the `SECRET_KEY` default is `change-me-in-production`. Running without an explicit key is unsafe; the default exists only so `docker compose up` works out of the box for a lab.

## 18. Environment variables

All documented in [installation.md](installation.md) and `.env.example`. Key set: `DATABASE_URL`, `SECRET_KEY`, `JWT_ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `CORS_ORIGINS`, `LOGIN_RATE_LIMIT`, `MAX_UPLOAD_SIZE_MB`, `MAX_UPLOAD_LINES`, `APP_ENV`, `APP_VERSION`.

## 19. Audit logging

- Every security-sensitive action is written to `audit_logs` through `app/services/audit.py.write_audit`: logins (success/failure), logout, user/role/active changes, rule changes, alert status transitions, investigation lifecycle, report generation (JSON and PDF), and log ingestion (ingest/upload/sample-import). Actions are enumerated in `AuditAction` (`app/models/audit.py`).
- Entries record: user id + username, action, resource type/id, client IP, timestamp, and a JSON details blob.
- Viewing is **admin-only** (`GET /api/audit-logs`), filterable by action/username/type/time, and exportable as CSV.
- **Limitation (documented):** the audit log is plain rows in the database. A determined database admin with write access could modify it; there is no hash-chaining or external WORM store. That is an acceptable boundary for this lab; not for regulated environments.

## 20. Database security

- The app connects with least-privilege intentions via a dedicated `DATABASE_URL`; credentials come from the environment.
- The ORM prevents injection (§8).
- Demo password hashes are produced at runtime by the same bcrypt code path that validates logins (the seed SQL ships only comments about credentials, not hashes — see `database/seed.sql`).
- **Limitation (documented):** schema is created by `Base.metadata.create_all` at startup (auto-migrations, no Alembic). For production, a migration framework and a dedicated, network-restricted DB role are recommended.

## 21. Database indexes (security/performance relevant)

Hot lookup paths are indexed in `app/models/` and mirrored where necessary:

- `users.username` — login lookups.
- `events.timestamp`, `events.event_type`, `events.source_ip`, `events.username` — filtering, dashboards, and reports.
- `alerts.alert_type`, `alerts.severity`, `alerts.status`, `alerts.created_at`, `alerts.event_id` (FK) — triage lists and report aggregations.
- `audit_logs.user_id`, `audit_logs.action`, `audit_logs.timestamp`, `audit_logs.resource_type` — audit search.
- `token_blacklist.jti` (unique) — revocation lookups.
- `rules.alert_type` — rule lookups.

## 22. Logging considerations

- Request/error details are only logged server-side by the application; clients receive sanitised responses.
- The ingest pipeline surfaces parse-unknown counts to operators (`unknown` in every ingest response) so malformed log feeds are observable.
- **Limitation (documented):** there is no structured request logger or centralised log shipping (no ELK/OpenTelemetry integration). Nginx access logs and uvicorn output are the operational trails.

## 23. Sensitive-data handling

- Passwords: bcrypt hashes only (§2).
- Tokens: held by the client in `localStorage` (`sentinelx_token`). **Limitation:** `localStorage` is exposed to any XSS and persists until explicitly removed; an HTTP-only Secure cookie with a CSRF strategy is the production-grade alternative.
- Audit details can contain usernames/IPs; they are stored server-side and only shown to admins.
- API responses are shaped by schemas that omit password hashes and other internals.

## 24. Security testing

- **Automated suite:** 120+ backend tests cover auth (login/register/logout/JWT/blacklist), RBAC (analyst vs admin `403`s), rate limiting (429 behaviour and window semantics), input validation (`422`s, upload caps), detection rules (SSH brute force, auth-failure spike, root login, SQLi, web attack wave, sudo, user lifecycle), alert workflow, investigations, reports (JSON + **PDF**, range & real-data assertions), CSV exports, and audit recording.
- Frontend verified by production build; no end-to-end browser harness is present.
- **Limitation (documented):** no dependency vulnerability scanner is wired into CI (`npm audit` / pip-audit are available but not automated), and there is no fuzzing harness around the parsers.

## 25. Threat model relationship

The controls above are each mapped to an asset/threat in [threat-model.md](threat-model.md) (A1–A9, constructed from the OWASP-oriented DREAD-style table). Read that first, then cross-reference the control sections here.

## 26. Known limitations (summary)

1. In-memory rate limit is per-process (single-worker only).
2. JWT blacklist rows are never purged (no sweep job).
3. `localStorage` token storage (XSS-exposed; no cookie/CsRF strategy).
4. No HSTS or CSP header yet; HSTS additionally needs HTTPS termination.
5. No structured log shipping or alerting integration.
6. No Alembic migrations (schema from `create_all`).
7. Audit log is not tamper-evident (plain DB rows).
8. No automated dependency auditing / fuzzing in CI.
9. Demo credentials are fixed & published (must be changed via user management before real use).

## 27. Production security recommendations

1. Set a strong random `SECRET_KEY` and unique `DATABASE_URL` (no defaults).
2. Run **behind HTTPS** (reverse proxy / TLS terminator) and enable HSTS; consider adding a CSP tuned to the app.
3. Change/remove the demo administrator immediately; enforce real password policy.
4. Run the API behind the rate-limit-aware proxy and, for multi-instance scale-out, back the login limiter with Redis.
5. Put a migration framework (Alembic) in place and use a dedicated, network-restricted DB role.
6. Move tokens to HTTP-only Secure cookies (+ CSRF) instead of `localStorage`.
7. Ship structured logs and automate dependency scanning and parser fuzzing in CI.
8. Add a regular sweep for expired blacklist rows.