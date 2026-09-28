# SentinelX

### Security Log Analysis & Threat Detection Platform

**SentinelX** is a full-stack SOC-style security log analysis and threat detection platform designed for ingesting, parsing, normalising, analysing, and investigating security events.

It provides a complete workflow from raw security logs to detected alerts, investigations, reports, and an optional AI-powered Security Assistant.

## 🌐 Live Demo

**Website:** https://sentinel-x-flax.vercel.app/

**Backend API:** https://sentinelx-backend-tim8.onrender.com/

---

## ✨ Features

### 🔐 Authentication & Security

- Secure HttpOnly cookie-based JWT authentication
- CSRF protection for state-changing requests
- Role-based access control
- `ADMIN` and `ANALYST` roles
- bcrypt password hashing
- Login and registration rate limiting
- Account-level login protection
- JWT validation and token revocation
- Trusted proxy handling for production deployments
- User-scoped security data isolation

### 📥 Security Log Ingestion

SentinelX supports security log ingestion from:

- File uploads
- Pasted log lines
- Sample security logs
- Manual investigation workflows

Supported upload formats:

- `.log`
- `.txt`

Uploaded files are validated for:

- File type
- File size
- Line limits
- Empty files
- Binary content
- UTF-8/text compatibility
- Recognizable security log entries

Invalid files are rejected before database writes.

Partial files can be processed while unrecognised lines are reported to the user.

### 🔎 Log Parsing & Normalisation

The detection pipeline parses and normalises security events from common log formats, including:

- SSH authentication logs
- Apache logs
- Nginx logs
- Linux authentication logs

Events are normalised into a common security-event model for detection and investigation.

### 🚨 Threat Detection

SentinelX uses a rule-based detection engine to identify suspicious activity such as:

- Brute-force authentication attempts
- Repeated failed logins
- Suspicious authentication behaviour
- Threshold-based security events
- Other configurable detection rules

Generated alerts are isolated by user/tenant so activity belonging to one account cannot appear in another user's investigation data.

### 🕵️ Investigations

Security analysts can:

- Review alerts
- Create investigations
- Update investigation status
- Add investigation notes
- Examine related security events
- Track investigation activity

Investigation and alert access is scoped to the authenticated user.

### 📊 Dashboard & Reports

The platform provides:

- Security event statistics
- Alert summaries
- Detection activity
- Investigation information
- Audit logs
- CSV evidence exports
- PDF security reports

Reports and dashboard aggregates are scoped to the authenticated user.

### 🤖 Security Assistant

SentinelX includes an optional read-only AI Security Assistant.

The assistant can answer questions about the authenticated user's SentinelX data using a fixed set of backend security tools.

Supported providers:

- Google Gemini
- OpenAI

The AI layer is designed with security boundaries including:

- Read-only tools
- User-scoped database queries
- No arbitrary SQL
- No arbitrary code execution
- Prompt-injection-resistant tool boundaries
- Bounded tool calls
- Bounded tool results
- Per-user AI rate limiting
- Request size limits
- Backend-only API keys
- Safe provider diagnostics
- No AI conversation persistence in the database

The provider can be selected through backend configuration.

Example:

```env
AI_ENABLED=true
AI_PROVIDER=gemini
GEMINI_MODEL=gemini-3.5-flash
GEMINI_API_KEY=your-key
```
