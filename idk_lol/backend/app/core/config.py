"""Application configuration using pydantic-settings.

All configuration comes from environment variables (.env for local dev).
Secrets are never hard-coded with real values; defaults are development-only.
"""
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "FDR Sentinel"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # Database: PostgreSQL in production; SQLite fallback for local development/tests
    DATABASE_URL: str = "sqlite:///./fdr_sentinel.db"

    # Security
    SECRET_KEY: str = "dev-secret-key-change-me-in-production"
    CSRF_SECRET_KEY: str = "dev-csrf-secret-key-change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Session cookies
    SESSION_COOKIE_NAME: str = "fdr_session"
    CSRF_COOKIE_NAME: str = "fdr_csrf"
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"

    # Document storage
    STORAGE_BACKEND: str = "local"  # local | s3
    LOCAL_STORAGE_PATH: str = "./storage"
    MAX_UPLOAD_BYTES: int = 25_000_000
    ALLOWED_CONTENT_TYPES: List[str] = ["application/pdf", "image/png", "image/jpeg"]

    # OCR engine: simulated | tesseract | paddleocr
    OCR_ENGINE: str = "simulated"
    TESSERACT_CMD: str | None = None

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60

    # Seed development data on startup
    SEED_DATA: bool = True

    @field_validator("COOKIE_SAMESITE")
    @classmethod
    def _validate_samesite(cls, v: str) -> str:
        allowed = {"lax", "strict", "none"}
        if v.lower() not in allowed:
            raise ValueError(f"COOKIE_SAMESITE must be one of {allowed}")
        return v.lower()

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    return Settings()