# SentinelX — Detection Rules

Rule definitions for the threat detection engine. Each file groups rules for a
log source category. Rules are loaded into the `detection_rules` table at
startup and can be enabled or disabled by administrators through the UI.

- `authentication.yaml` — auth and SSH brute-force detection
- `ssh.yaml` — SSH-specific rules
- `web.yaml` — HTTP / web server anomaly rules
- `system.yaml` — system and privilege related rules