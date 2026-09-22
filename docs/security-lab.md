# SentinelX — Controlled security lab

A safe, local demonstration environment for SentinelX. Use it to show how the
platform ingests, normalises, detects, and investigates security events —
**without touching real systems**. Every scenario below runs entirely on
bundled samples or locally generated synthetic log text, on machines you own.
SentinelX contains no capability to attack external systems.

---

## Purpose

The lab exists to:

- Demonstrate the full detection pipeline from log line to resolved alert.
- Exercise the detection rules with reproducible, benign data.
- Provide a repeatable walkthrough for interviews, demos, and training.
- Keep the security-testing surface strictly inside the developer's own
  environment.

## Environment

Simulated/synthetic data flows through the exact same path a real SOC feed
would take:

```
Synthetic/sample source
        ↓
Sample security events / logs
        ↓
SentinelX ingestion  (POST /api/logs/ingest | /upload | /import)
        ↓
Parser              (syslog, SSH, sudo, Apache, nginx)
        ↓
Normaliser          (validate, trim, type-check, timestamp tz)
        ↓
Detection engine    (rules × time-window thresholds)
        ↓
Alert               (severity, status, deduplicated per window)
        ↓
Investigation       (notes, status transitions, resolution)
```

## Prerequisites

- SentinelX running. Either:
  - `docker compose up --build` (stack on `http://localhost:8080`), or
  - local dev: backend + `npm run dev` frontend (see [installation.md](installation.md)).
- Postgres reachable (compose runs it; `sentinelx-test-pg` container for development tests).
- A login: demo `admin` / `Admin@12345` or `analyst` / `Analyst@12345`
  (from the demo seed) — change these before any real use.

## Lab setup

1. Start the stack (see above).
2. Open the web UI, log in.
3. From **Reports** (any window), optionally **Download PDF** to produce the
   printed report that this lab populates.

All sample files live in [`sample_logs/`](../sample_logs/). They may be loaded
three ways:

**A. UI** — **Logs → Import bundled sample** (dropdown: `auth`, `apache`,
`nginx`, `ssh`). Repeat for each scenario.

**B. API (curl)** — after logging in:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@12345"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
for sample in auth apache nginx ssh; do
  curl -s -X POST "http://localhost:8080/api/logs/import?sample=$sample" \
    -H "Authorization: Bearer $TOKEN"
done
```

**C. File upload** — **Logs → Upload**, or the synthetic generators below
produce a file you upload the same way.

## Controlled scenarios

Each scenario maps to a sample (or a tiny synthetic generator) that triggers a
known detection. Expected alerts below were verified against the shipped rules.

### 1. SSH brute-force simulation — `ssh.log`

25 lines: 23 failed SSH password attempts from `203.0.113.10`, then successful
logins. Ingestion creates **5 alerts**:

| Alert | Severity | Source |
|---|---|---|
| SSH Brute Force Attempt | HIGH | 203.0.113.10 |
| Root SSH Login | MEDIUM | 203.0.113.10, 198.51.100.22 |
| User Account Created | LOW | — |
| Privilege Escalation via Sudo | MEDIUM | — |

The brute force fires because 5+ `SSH_LOGIN_FAILURE` events arrive from one IP
within 300 s (`rules/authentication.yaml`, threshold 5).

### 2. Repeated authentication failures — `auth.log` (first 3 lines)

Two generic `authentication failure` lines plus a `Maximum authentication
attempts exceeded` line from `198.51.100.77`. Run the full `auth.log` for the
whole scenario set below; to exercise the **Authentication Failure Spike** rule
at lower volume, feed more AUTH_FAILURE lines from one IP with the synthetic
generator (threshold 10 in 300 s) — see "Synthetic generation".

### 3. Suspicious successful login — `auth.log` (and `ssh.log`)

`Accepted password for alice from 192.0.2.10` (and the accepted `admin`/`deploy`
logins in `ssh.log`) produce **Root SSH Login** (MEDIUM) alerts on
`SSH_LOGIN_SUCCESS`.

### 4. HTTP anomaly simulation — `apache.log`

15 lines of mixed web traffic. A single crafted request
`GET /admin/index.php?user=union select password from users` triggers
**SQL Injection Attempt** (CRITICAL) on one hit. `nginx.log` (server scanner
noise — 10 identical 404s plus health checks) is included to show *absence*:
it creates **0 alerts**, because none of the thresholds are met.

### 5. Privilege activity simulation — `auth.log` (and `ssh.log`)

Sudo invocations (`apt-get update`, a `newusers` run, a `chmod 777 /etc/shadow`)
raise **Privilege Escalation via Sudo** (MEDIUM); the `useradd
… name=tempadmin` line raises **User Account Created** (LOW).

### Expected detection summary

| Sample | Events | Alerts | Alerts produced |
|---|---|---|---|
| `auth.log` | 8 | 4 | Root SSH Login; User Account Created; Privilege Escalation via Sudo ×2 |
| `apache.log` | 15 | 1 | SQL Injection Attempt (CRITICAL) |
| `nginx.log` | 12 | 0 | — (scanner noise below thresholds) |
| `ssh.log` | 25 | 5 | SSH Brute Force Attempt (HIGH); Root SSH Login ×2; User Account Created; Privilege Escalation via Sudo |

## Synthetic generation (safe, local-only)

These generate **synthetic log text** into a local file — nothing is sent to,
or executed on, any real host. Upload the file via **Logs → Upload** (or the
API) and the same rules fire.

SSH brute-force burst from one IP:

```bash
ip="203.0.113.77"; out=/tmp/lab_bruteforce.log
: > "$out"
for port in $(seq 50000 50024); do
  printf 'Sep 22 06:%02d:%02d labhost sshd[%d]: Failed password for admin from %s port %s ssh2\n' \
    $(( (port % 4) )) $(( (port % 60) )) "$port" "$ip" "$port" >> "$out"
done
wc -l "$out"
```

Authentication-failure spike (pushes the AUTH_FAILURE rule past its threshold):

```bash
ip="198.51.100.88"; out=/tmp/lab_spike.log
: > "$out"
for i in $(seq 1 12); do
  printf 'Sep 22 07:00:%02d labhost sshd[%d]: authentication failure; logname= uid=0 euid=0 tty=sshd ruser= rhost=%s user=root\n' \
    "$i" "$(( 3000 + i ))" "$ip" >> "$out"
done
wc -l "$out"
```

Privilege / account activity:

```bash
out=/tmp/lab_priv.log
printf 'Sep 22 08:00:00 labhost sudo[4201]: alice : TTY=tty1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart sshd\n' > "$out"
printf 'Sep 22 08:00:05 labhost useradd[4202]: new user: name=svcbackup, UID=1100, GID=1100, home=/home/svcbackup, shell=/bin/bash\n' >> "$out"
wc -l "$out"
```

Uploading via the API:

```bash
curl -s -X POST http://localhost:8080/api/logs/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/lab_bruteforce.log"
```

## Investigation workflow

1. **Alerts** page → filter by severity or type, e.g. the **SSH Brute Force
   Attempt (HIGH)** alert.
2. Open the alert detail: it shows the related event, rule, source IP, and
   description.
3. **Create investigation** from the alert (assigns analyst, links events).
4. Add **notes** as you close the loop (audit-logged as `NOTE_ADDED`).
5. Change the alert status through **Investigating** → **Resolved**; resolution
   time is captured and reflected in **Reports** (`avg_resolution_minutes`).
6. Return to **Reports** and **Download PDF** — the PDF reflects these alerts,
   severities, sources, and (if resolved) resolution times for the window.

## Cleanup

- Resolve or delete lab alerts through the UI (or clear the database).
- Remove generated files:

  ```bash
  rm -f /tmp/lab_bruteforce.log /tmp/lab_spike.log /tmp/lab_priv.log
  ```

- For a full reset with compose: `docker compose down -v` (drops the Postgres
  volume) then `docker compose up --build`.

## Safety boundaries

- **Only bundled samples and locally generated synthetic text are used.** No
  attack tooling is included or executed against other systems.
- The lab listens on loopback/`localhost` only in dev (compose publishes ports
  on the host; keep it behind your firewall or VPN when demoing).
- Demo credentials are fixed and published — change them via **Users** (admin)
  before connecting the lab to anything real.
- Anything you ingest stays in your own database; exports (CSV/PDF) are
  generated from that data only.
- Detection rules are declarative YAML — they observe, they never act on the
  outside world. See [security.md](security.md) for the full control inventory
  and known limitations.