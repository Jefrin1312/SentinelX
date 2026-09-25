"""Application configuration loaded from environment variables.

All secrets, database credentials and tunable settings are read from the
environment (or a .env file) so that nothing sensitive is hardcoded in the
source code. In containerised deployments these come from docker-compose
environment values.
"""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the SentinelX backend."""

    APP_NAME: str = "SentinelX"
    APP_ENV: str = "development"
    APP_VERSION: str = "0.4.0"
    API_PREFIX: str = "/api"
    DEBUG: bool = False

    # Database — SQLAlchemy URL. Example values in .env.example:
    # postgresql+psycopg://sentinelx:password@localhost:5432/sentinelx
    DATABASE_URL: str = (
        "postgresql+psycopg://sentinelx:change_me"
        "@127.0.0.1:5432/sentinelx"
    )

    # Security
    SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Comma separated IPs/CIDRs of reverse proxies. The X-Forwarded-For header
    # is only trusted when the immediate peer is one of these; otherwise the
    # real socket peer is used so headers cannot be spoofed to bypass rate
    # limiting or poison audit logs.
    TRUSTED_PROXIES: str = ""

    # Brute-force protection for account creation and per-account logins.
    # "N/second", "N/minute" or "N/hour"; empty or "0" disables.
    REGISTER_RATE_LIMIT: str = "10/hour"
    LOGIN_ACCOUNT_RATE_LIMIT: str = "30/minute"

    # Only send the HttpOnly/Secure auth cookie over HTTPS. Development runs on
    # plain HTTP (Vite proxy / docker-compose on localhost) so this must stay
    # False there; production deployments served over HTTPS must set it True.
    COOKIE_SECURE: bool = False

    # CORS — comma separated list of allowed origins.
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Uploaded log limits
    MAX_UPLOAD_SIZE_MB: int = 5
    MAX_UPLOAD_LINES: int = 5000
    SAMPLE_LOGS_DIR: str = "sample_logs"

    # Detection rule bundles directory (YAML files loaded at startup)
    RULES_DIR: str = "rules"

    # Slow down failed login attempts (simple brute-force protection).
    LOGIN_RATE_LIMIT: str = "10/minute"

    # Security Assistant (read-only, user-scoped). Disabled unless AI_ENABLED
    # is true and a provider key is supplied. The key is only ever read by the
    # backend provider; it is never exposed to the client or logged.
    AI_ENABLED: bool = False
    AI_PROVIDER: str = "openai"
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_KEY: SecretStr = SecretStr("")
    # Per-user assistant budget. "N/second", "N/minute" or "N/hour"; "0" disables.
    AI_RATE_LIMIT: str = "20/minute"
    AI_MAX_TOOL_CALLS: int = Field(default=8, ge=0, le=20)
    AI_MAX_CONTEXT_RECORDS: int = Field(default=20, ge=1, le=50)
    AI_MAX_MESSAGE_LENGTH: int = Field(default=2000, ge=1, le=8000)
    AI_MAX_OUTPUT_TOKENS: int = Field(default=800, ge=64, le=4096)
    AI_MAX_TOOL_RESULT_CHARS: int = Field(default=8000, ge=500, le=40000)
    AI_REQUEST_TIMEOUT_SECONDS: int = Field(default=20, ge=1, le=120)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Parsed list of allowed CORS origins."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (reads .env once)."""
    return Settings()