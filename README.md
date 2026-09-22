# SentinelX

## Security Log Analysis and Threat Detection Platform

SentinelX is a professional SOC-style web application for ingesting, parsing,
normalising and analysing security logs, detecting suspicious activity through
a rule-based detection engine, and managing investigations of generated
alerts. It is designed as a polished, full-stack cybersecurity portfolio
project.

> Early development build — core pipeline is under construction.

## Quick start

```bash
docker compose up --build
```

- Frontend: http://localhost:8080
- Backend API docs (Swagger): http://localhost:8000/api/docs

## Stack

- Frontend: React + Vite + Recharts
- Backend: FastAPI + SQLAlchemy + Pydantic
- Database: PostgreSQL
- Auth: JWT + bcrypt, role based access control (ADMIN / ANALYST)
- Infra: Docker Compose

See `docs/` for architecture, API, installation, threat model and interview
documentation.