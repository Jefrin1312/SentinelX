"""Platform settings display schema (administrator view).

Only operational, non-secret configuration is exposed. Database credentials,
JWT signing keys, and other secrets never leave the server.
"""

from pydantic import BaseModel


class PlatformSettings(BaseModel):
    app_name: str
    app_env: str
    app_version: str
    api_prefix: str
    debug: bool
    jwt_expire_minutes: int
    login_rate_limit: str
    max_upload_mb: int
    max_upload_lines: int
    sample_logs_dir: str
    rules_dir: str
    rule_count: int
    user_count: int