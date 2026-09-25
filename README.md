# SentinelX

## Security Log Analysis and Threat Detection Platform

SentinelX is a professional SOC-style web application for ingesting, parsing,
normalising and analysing security logs, detecting suspicious activity through
a rule-based detection engine, and managing investigations of generated
alerts. Reports can be downloaded as CSV evidence or as a PDF security report.
An optional read-only Security Assistant answers questions about your own data
using a fixed set of tenant-scoped backend tools. It is designed as a polished,
full-stack cybersecurity portfolio project.

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
- Auth: HttpOnly cookie JWT + bcrypt, role based access control (ADMIN / ANALYST)
- AI (optional): read-only, tenant-scoped tools behind `POST /api/ai/chat`
- Infra: Docker Compose

See `docs/` for architecture, API, installation, threat model, security
controls, the controlled security lab, and interview documentation.