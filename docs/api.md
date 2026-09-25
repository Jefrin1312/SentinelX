# SentinelX — API Reference

Base URL: `/api`. Interactive documentation is served at `/api/docs` (Swagger)
and `/api/redoc`, generated from the FastAPI app at runtime.

## Conventions

- **Authentication** — an HttpOnly, SameSite session cookie issued by
  `POST /api/auth/login`. The JWT never touches JavaScript, `localStorage` or
  request headers; the frontend relies on the cookie being sent automatically.
  State-changing requests must echo the `sentinelx_csrf` cookie in an
  `X-CSRF-Token` header (double-submit). A `401` response clears the client
  session and redirects to `/login`.
- **Authorization** — enforced server side on every request. `analyst` = any
  authenticated, active user (ANALYST or ADMIN); `admin` = ADMIN only.
- **Pagination** — list endpoints accept `skip` and `limit` and return
  `{ total, items }`. Defaults and maximums vary by endpoint.
- **Filtering** — list endpoints accept query filters (`status`, `severity`,
  `search`, `from_time`, `to_time`, …). Query strings and matching behaviour
  are documented per endpoint below and interactively in Swagger.
- **Timestamps** — ISO-8601, timezone-aware UTC.
- **Errors** — JSON `{"detail": "..."}` with a proper status code
  (`400/401/403/404/409/413/422/429/500`). Unhandled exceptions return a
  generic `500` without leaking internals.

Access legend: `Public` · `Auth` (any authenticated user) · `Analyst`
(ANALYST or ADMIN) · `Admin` (ADMIN only).

---

## Health

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/health` | Public | Backend status and database connectivity |
| GET | `/api/` | Public | Root pointer to the docs (not in OpenAPI) |

`GET /api/health` returns `{status, application, environment, database, version}`.

---

## Authentication

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| POST | `/api/auth/register` | Public | Create an account (always ANALYST) |
| POST | `/api/auth/login` | Public | Log in and receive a JWT (rate limited) |
| POST | `/api/auth/logout` | Auth | Revoke the current JWT |
| GET | `/api/auth/me` | Auth | Current user profile |
| PATCH | `/api/auth/me` | Auth | Update own email |
| POST | `/api/auth/change-password` | Auth | Change own password (revokes session) |

**POST /api/auth/register**

```json
{
  "username": "jsmith",
  "email": "jsmith@example.com",
  "password": "Str0ngPass!word"
}
```

- `username`: 3–50 chars, `[A-Za-z0-9_.-]` only.
- `password`: 10–72 chars.
- Returns `201` with `{access_token, token_type, expires_in, user}`.
- `409` if the username or email already exists; `422` for invalid input.

**POST /api/auth/login**

```json
{ "username": "admin", "password": "Admin@12345" }
```

- Returns `200` with `{access_token, token_type, expires_in, user}`.
- `401` on invalid credentials; `403` if the account is disabled.
- **Rate limited** per client IP: exceeding `LOGIN_RATE_LIMIT`
  (default `10/minute`) returns `429`. The limiter is in-memory fixed-window
  and honours `X-Forwarded-For`.
- Successful and failed logins are recorded in the audit log.

**POST /api/auth/logout** — blacklists the token `jti`; returns `204`. The
token then fails with `401 Token has been revoked` even before its `exp`.

**POST /api/auth/change-password** — body `{current_password, new_password}`
(`new_password` 10–72 chars). On success the presented JWT is blacklisted, so
the client must log in again.

---

## Users (admin)

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/users` | Admin | List/search/filter users |
| PATCH | `/api/users/{user_id}` | Admin | Change role or enable/disable |

**GET /api/users** — filters: `search` (username/email), `role`
(`ADMIN`/`ANALYST`), `active`; pagination `skip`/`limit` (default 25, max 100).

**PATCH /api/users/{user_id}** — body:

```json
{ "role": "ANALYST", "is_active": false }
```

Either field is optional. Guards against disabling or demoting the last active
administrator (`400`). Each change writes `USER_ROLE_CHANGED`,
`USER_ENABLED`, or `USER_DISABLED` to the audit log.

---

## Dashboard

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/dashboard/summary` | Analyst | Live aggregate statistics |
| GET | `/api/dashboard/timeline` | Analyst | Hourly event/alert counts |

**GET /api/dashboard/summary** — totals, last-24h counts, severity/status
breakdowns, top 8 source IPs and event types, latest 50 events and 20 alerts.
All values are computed with SQL aggregates at request time.

**GET /api/dashboard/timeline?hours=24** — zero-filled hourly buckets
(`hours` 1–168) with event counts and per-severity alert counts, aligned to UTC.

---

## Logs & events

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| POST | `/api/logs/ingest` | Analyst | Ingest raw log lines |
| POST | `/api/logs/upload` | Analyst | Upload a plain-text log file |
| POST | `/api/logs/import` | Analyst | Import a bundled sample log |
| GET | `/api/logs` | Analyst | List security events |
| GET | `/api/logs/export` | Analyst | Export events as CSV |
| GET | `/api/logs/{event_id}` | Analyst | Get one event |

**POST /api/logs/ingest**

```json
{ "lines": ["Failed password for root from 192.168.1.50 port 55012 ssh2"], "source": "MANUAL" }
```

- `lines`: 1–2000 entries; `source` defaults to `MANUAL`.
- Returns `201` `{total_lines, parsed, unknown, events_created, alerts_created, event_ids}`.
- Each stored event is passed through the detection engine; rule matches may
  create alerts in the same response (`alerts_created`).

**POST /api/logs/upload** — `multipart/form-data` with a `file` field.
Rejects files above `MAX_UPLOAD_SIZE_MB` (default 5 MB) or
`MAX_UPLOAD_LINES` (default 5000) with `413`. The filename is never trusted —
content is treated purely as data.

**POST /api/logs/import?sample=ssh** — one of `ssh`, `apache`, `nginx`,
`auth`. Reads the matching `sample_logs/<name>.log` for demos; `404` if the
sample is unavailable.

**GET /api/logs** — filters: `search` (message/source_ip/username),
`event_type`, `source`, `source_ip`, `username`, `status`, `severity`,
`from_time`, `to_time`; `skip`/`limit` (default 50, max 500), newest first.

**GET /api/logs/export** — same filters, returns a CSV attachment.

Common `event_type` values: `SSH_LOGIN_FAILURE`, `SSH_LOGIN_SUCCESS`,
`AUTH_FAILURE`, `SUDO_COMMAND`, `USER_CREATED`, `USER_DELETED`,
`HTTP_REQUEST`, `HTTP_SUSPICIOUS_REQUEST`, `UNKNOWN`.

---

## Alerts

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/alerts` | Analyst | List alerts |
| GET | `/api/alerts/export` | Analyst | Export alerts as CSV |
| GET | `/api/alerts/{alert_id}` | Analyst | Alert detail + related event |
| PATCH | `/api/alerts/{alert_id}/status` | Analyst | Transition alert status |

**GET /api/alerts** — filters: `status` (`OPEN`/`INVESTIGATING`/`RESOLVED`),
`severity`, `alert_type`, `source_ip`, `search`, `from_time`, `to_time`;
`skip`/`limit` (default 50, max 500), newest first.

**GET /api/alerts/{alert_id}** — returns the alert plus its `rule_name`,
related `event`, and current `investigation` (if any).

**PATCH /api/alerts/{alert_id}/status**

```json
{ "status": "INVESTIGATING", "note": "Triaging a source IP" }
```

Sets `resolved_at` when moving to `RESOLVED`, clears it otherwise, and writes
`ALERT_STATUS_CHANGED` to the audit log. `404` if the alert does not exist.

Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
Status lifecycle: `OPEN → INVESTIGATING → RESOLVED`.

---

## Detection rules

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/rules` | Analyst | List/search rules |
| POST | `/api/rules` | Admin | Author a new rule |
| PATCH | `/api/rules/{rule_id}` | Admin | Enable or disable a rule |
| POST | `/api/rules/reload` | Admin | Reload rule bundles from disk |

**GET /api/rules** — filters: `category`, `enabled`, `search`; `skip`/`limit`
(default 100, max 500).

**POST /api/rules** — body:

```json
{
  "name": "Web Brute Force Login",
  "description": "Repeated failed HTTP logins from one source.",
  "category": "web",
  "severity": "HIGH",
  "enabled": true,
  "threshold": 8,
  "time_window": 300,
  "rule_definition": {
    "event_type": "HTTP_SUSPICIOUS_REQUEST",
    "key": "source_ip",
    "reason": null,
    "signature": "sql_injection"
  }
}
```

- `name`: 3–120 chars, `[A-Za-z0-9 _\-.()/]` only, must be unique (`409`).
- `category`: `authentication`, `ssh`, `web`, `system`, `general`.
- `severity`: `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`.
- `threshold`: 1–100000; `time_window`: 1–604800 seconds.
- `rule_definition.key`: `source_ip` or `username`.
- Writes the rule to `rules/{category}.yaml`, reloads the ruleset, and records
  `RULE_CREATED`.

**PATCH /api/rules/{rule_id}** — body `{ "enabled": false }`. Writes
`RULE_ENABLED`/`RULE_DISABLED`.

**POST /api/rules/reload** — re-reads all `rules/*.yaml` bundles (upsert by
name) and returns `{loaded, updated, skipped}`. Records `RULES_RELOADED`.

Rule files are declarative YAML; see `rules/README.md` for the bundle format.

---

## Investigations

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| POST | `/api/investigations` | Analyst | Open an investigation on an alert |
| GET | `/api/investigations` | Analyst | List investigations |
| GET | `/api/investigations/{id}` | Analyst | Detail with alert + notes |
| PATCH | `/api/investigations/{id}` | Analyst | Update status/summary/assignee |
| POST | `/api/investigations/{id}/notes` | Analyst | Add a note |

**POST /api/investigations** — body `{ "alert_id": 12, "summary": "..." }`.
Returns `201`; `404` if the alert does not exist, `409` if one already exists
for the alert. Opening an investigation promotes an `OPEN` alert to
`INVESTIGATING` and records `INVESTIGATION_CREATED` (plus
`ALERT_STATUS_CHANGED` when the alert moved).

**GET /api/investigations** — filters: `status`, `alert_id`, `assigned_to`,
`search`; `skip`/`limit` (default 50, max 500).

**GET /api/investigations/{id}** — detail including the related alert headline
and its note thread.

**PATCH /api/investigations/{id}** — body:

```json
{ "status": "RESOLVED", "summary": "Confirmed brute force; block source.", "assigned_to": 3 }
```

Statuses: `OPEN`, `INVESTIGATING`, `RESOLVED`. Records
`INVESTIGATION_UPDATED`.

**POST /api/investigations/{id}/notes** — body `{ "note": "..." }`
(1–4000 chars). Returns `201` and records `NOTE_ADDED`.

---

## Audit log (admin)

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/audit-logs` | Admin | Search/filter the audit trail |
| GET | `/api/audit-logs/export` | Admin | Export the audit trail as CSV |

**GET /api/audit-logs** — filters: `action`, `username`, `resource_type`,
`search`, `from_time`, `to_time`; `skip`/`limit` (default 50, max 500),
newest first.

**GET /api/audit-logs/export** — same filters, CSV attachment (up to 50,000
rows).

Recorded actions include: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`,
`USER_CREATED`, `USER_ROLE_CHANGED`, `USER_ENABLED`, `USER_DISABLED`,
`PROFILE_UPDATED`, `PASSWORD_CHANGED`, `RULE_CREATED`, `RULE_ENABLED`,
`RULE_DISABLED`, `RULES_RELOADED`, `ALERT_STATUS_CHANGED`,
`INVESTIGATION_CREATED`, `INVESTIGATION_UPDATED`, `NOTE_ADDED`,
`REPORT_GENERATED`, `LOGS_INGESTED`.

---

## Reports

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/reports/summary` | Analyst | Aggregated report for a date range |
| GET | `/api/reports/export` | Analyst | Download the report over a date range as a PDF |

**GET /api/reports/summary?days=7&topn=10**

- `days`: 1–90 (default 7); `topn`: 1–25 (default 10).
- Returns totals, `avg_resolution_minutes`, zero-filled daily event and
  alert series, `top_alert_types`, `by_severity`, `by_status`,
  `top_source_ips`, and `top_event_types`.
- Records `REPORT_GENERATED` in the audit log with the acting user and client IP.

**GET /api/reports/export?days=7&topn=10**

- Same parameters and same live aggregates as `/summary`, rendered as a
  downloadable **PDF** (`application/pdf`, `Content-Disposition: attachment`)
  with the report period, totals, severity/status breakdowns, top alert types
  (most-triggered rules), top source IPs, top event types, daily
  event/alert summary, and generation timestamp.
- Analysts and admins may download; unauthenticated requests return `401`.
- Records `REPORT_GENERATED` (resource `pdf`) in the audit log.

```bash
curl -s -OJ \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/reports/export?days=7"
```

---

## Security Assistant

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| POST | `/api/ai/chat` | Analyst | Ask a natural-language question about your own security data |

The assistant is read-only. It answers from records the **authenticated caller**
already owns, using a fixed set of backend tools; it can never read another
user's data, execute SQL or shell commands, or change any state.

**POST /api/ai/chat**

```json
{ "message": "What is happening in my environment today?", "conversation_id": "5c2c…" }
```

- `message`: 1–`AI_MAX_MESSAGE_LENGTH` characters (default 2000).
- `conversation_id`: optional UUID. It is an **opaque correlation id only** —
  the backend keeps no conversation, history or prompt state, and the value is
  never used for authorization. The client may keep its own transcript and
  re-send the same id with follow-up questions.
- Any other field (including `user_id`) is rejected with `422`. The acting user
  comes from the session cookie, never from the request body.
- Returns `{ message, conversation_id, sources }`, where `sources` lists the
  events, alerts, investigations, notes and rules that grounded the answer.

Security properties:

- Requires an active session (`401` otherwise) and a valid CSRF token (`403`).
- Per-user rate limited via `AI_RATE_LIMIT` (`429` when exceeded).
- Bounded work per request: `AI_MAX_TOOL_CALLS` tool calls and
  `AI_MAX_CONTEXT_RECORDS` records, each result capped at
  `AI_MAX_TOOL_RESULT_CHARS`.
- Every tool re-applies the ownership predicate, so a foreign record ID is
  reported as not found rather than returned.
- Record text (messages, descriptions, notes, usernames) is passed to the model
  as untrusted data and can never become an instruction.
- Disabled or unconfigured deployments return `503`.
- Records `AI_QUERY` in the audit log with the acting user, client IP, outcome,
  tool names and token counts — never the question or the answer.

Requires `AI_ENABLED=true` and `AI_API_KEY`; see `.env.example`.

---

## Platform settings (admin)

| Method | Path | Access | Description |
| ------ | ---- | ------ | ----------- |
| GET | `/api/settings` | Admin | Read-only view of runtime configuration |

Returns non-secret configuration: `app_name`, `app_env`, `app_version`,
`api_prefix`, `debug`, `jwt_expire_minutes`, `login_rate_limit`,
`max_upload_mb`, `max_upload_lines`, `sample_logs_dir`, `rules_dir`,
`rule_count`, `user_count`. `SECRET_KEY` and `DATABASE_URL` are never exposed
(the response is explicitly asserted to be free of them).