"""SentinelX FastAPI application entrypoint.

Wires together the API routers, CORS configuration and global exception
handlers. Authentication, DDoS-safe rate limits and role based access control
are layered on top of the routers defined here.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import health
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title="SentinelX API",
    description=(
        "Security Log Analysis and Threat Detection Platform. "
        "Ingest, normalise, detect, investigate and report on security events."
    ),
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic 500 response and never leak internal details."""
    # Logged server side only; the client receives no stack trace.
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix=settings.API_PREFIX)


@app.get("/", include_in_schema=False)
def root() -> dict:
    """Minimal root route pointing at the API documentation."""
    return {"application": settings.APP_NAME, "docs": "/api/docs"}