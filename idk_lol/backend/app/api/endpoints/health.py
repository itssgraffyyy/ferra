"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health", tags=["health"])
def health():
    return {
        "status": "ok",
        "service": "fdr-sentinel",
        "environment": settings.ENVIRONMENT,
        "database": settings.DATABASE_URL.split("://")[0] if settings.DATABASE_URL else "unknown",
    }