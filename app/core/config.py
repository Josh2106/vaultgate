"""Application settings.

All configuration is read from environment variables prefixed with ``VG_`` (or a
``.env`` file in development). Settings are validated at startup so that an
insecure production configuration fails fast instead of silently running.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class EmailBackend(StrEnum):
    CONSOLE = "console"
    MEMORY = "memory"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------ general
    app_name: str = "vaultgate"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    log_level: str = "INFO"
    log_json: bool = True
    public_base_url: str = "http://localhost:8000"

    # ------------------------------------------------------------------ storage
    database_url: str = "sqlite+aiosqlite:///./vaultgate.db"
    database_echo: bool = False
    database_pool_size: int = Field(default=10, ge=1)
    redis_url: str | None = None

    # ------------------------------------------------------------------ JWT
    jwt_keys_dir: Path = Path("./.keys/jwt")
    jwt_active_kid: str | None = None
    jwt_auto_generate: bool = True
    jwt_issuer: str = "vaultgate"
    jwt_audience: str = "vaultgate-api"
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=60 * 60 * 24 * 14, ge=3600)
    mfa_token_ttl_seconds: int = Field(default=300, ge=60, le=900)

    # ------------------------------------------------------------------ crypto
    master_key_file: Path = Path("./.keys/master-keys.json")
    master_key_auto_generate: bool = True

    # ------------------------------------------------------------------ passwords
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65536, ge=8)
    argon2_parallelism: int = Field(default=4, ge=1)
    password_min_length: int = Field(default=12, ge=8)
    lockout_threshold: int = Field(default=5, ge=1)
    lockout_seconds: int = Field(default=900, ge=1)
    require_verified_email: bool = True
    email_token_ttl_seconds: int = Field(default=60 * 60 * 24, ge=60)
    email_backend: EmailBackend = EmailBackend.CONSOLE

    # ------------------------------------------------------------------ HTTP hardening
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    max_body_bytes: int = Field(default=256 * 1024, ge=1024)
    trusted_proxy_hops: int = Field(default=0, ge=0, le=5)
    hsts_enabled: bool = False

    rate_limit_enabled: bool = True
    rate_limit_ip_capacity: int = Field(default=120, ge=1)
    rate_limit_ip_refill_per_sec: float = Field(default=2.0, gt=0)
    rate_limit_key_capacity: int = Field(default=600, ge=1)
    rate_limit_key_refill_per_sec: float = Field(default=10.0, gt=0)
    rate_limit_auth_capacity: int = Field(default=10, ge=1)
    rate_limit_auth_refill_per_sec: float = Field(default=0.2, gt=0)

    idempotency_ttl_seconds: int = Field(default=60 * 60 * 24, ge=60)

    # ------------------------------------------------------------------ observability
    metrics_enabled: bool = True
    metrics_token: SecretStr | None = None
    otel_enabled: bool = False
    otel_exporter_endpoint: str | None = None
    otel_service_name: str = "vaultgate-api"

    # ------------------------------------------------------------------ validators
    @model_validator(mode="before")
    @classmethod
    def _split_cors(cls, data: object) -> object:
        if isinstance(data, dict):
            raw = data.get("cors_origins")
            if isinstance(raw, str):
                data["cors_origins"] = [o.strip() for o in raw.split(",") if o.strip()]
        return data

    @model_validator(mode="after")
    def _check_production_safety(self) -> Self:
        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origins are not allowed; list origins explicitly.")
        if self.is_production:
            problems: list[str] = []
            if self.database_url.startswith("sqlite"):
                problems.append("SQLite is not supported in production")
            if self.jwt_auto_generate:
                problems.append("VG_JWT_AUTO_GENERATE must be false in production")
            if self.master_key_auto_generate:
                problems.append("VG_MASTER_KEY_AUTO_GENERATE must be false in production")
            if self.debug:
                problems.append("VG_DEBUG must be false in production")
            if not self.hsts_enabled:
                problems.append("VG_HSTS_ENABLED must be true in production")
            if problems:
                raise ValueError("Insecure production configuration: " + "; ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.environment in {Environment.PRODUCTION, Environment.STAGING}

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def api_key_prefix(self) -> str:
        return "vg_live_" if self.is_production else "vg_test_"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
