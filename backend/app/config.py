"""Application configuration loaded from environment variables.

All secrets, database credentials and tunable settings are read from the
environment (or a .env file) so that nothing sensitive is hardcoded in the
source code. In containerised deployments these come from docker-compose
environment values.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the SentinelX backend."""

    APP_NAME: str = "SentinelX"
    APP_ENV: str = "development"
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

    # CORS — comma separated list of allowed origins.
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Uploaded log limits
    MAX_UPLOAD_SIZE_MB: int = 5
    MAX_UPLOAD_LINES: int = 5000
    SAMPLE_LOGS_DIR: str = "sample_logs"

    # Slow down failed login attempts (simple brute-force protection).
    LOGIN_RATE_LIMIT: str = "10/minute"

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