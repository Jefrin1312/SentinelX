# SentinelX

## Security Log Analysis and Threat Detection Platform

SentinelX is a professional SOC-style web application for ingesting, parsing,
normalising and analysing security logs, detecting suspicious activity through
a rule-based detection engine, and managing investigations of generated
alerts. It is designed as a polished, full-stack cybersecurity portfolio
project.

> Development build — the detection pipeline is actively evolving. Demo
> credentials (below) are seeded on startup and are intended for local use only.

## Quick start

```bash
docker compose up --build
```

- Frontend: http://localhost:8080
- Backend API docs (Swagger): http://localhost:8000/api/docs

Demo accounts are created automatically on first start:

| Role    | Username  | Password      |
| ------- | --------- | ------------- |
| Admin   | `admin`   | `Admin@12345` |
| Analyst | `analyst` | `Analyst@12345` |

## Stack

- Frontend: React + Vite + Recharts
- Backend: FastAPI + SQLAlchemy + Pydantic
- Database: PostgreSQL
- Auth: JWT + bcrypt, role based access control (ADMIN / ANALYST)
- Infra: Docker Compose

See `docs/` for architecture, API, installation, threat model and interview
documentation.