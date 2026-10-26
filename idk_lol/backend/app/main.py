"""FDR Sentinel FastAPI application."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.deps import settings
from app.api.middleware.audit import AuditMiddleware
from app.api.middleware.csrf import CSRFMiddleware
from app.api.middleware.errors import ErrorHandlerMiddleware
from app.api.endpoints import (
    auth,
    health,
    institutions,
    obligations,
    instruments,
    documents,
    ocr,
    reconciliation,
    policy,
    findings,
    cases,
    audit,
)
from app.core.logging import get_logger, setup_logging

logger = get_logger("app.main")


def create_app() -> FastAPI:
    setup_logging(level=settings.LOG_LEVEL)

    app = FastAPI(
        title="FDR Sentinel",
        description="Secure Financial Deposit Receipt (FDR) Compliance Platform — AICTE SIH26265",
        version="1.0.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # CORS (restrict origins in production via environment)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware order: errors (outermost) -> audit -> csrf -> cors -> routes
    app.add_middleware(ErrorHandlerMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(CSRFMiddleware)

    # Routers
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(institutions.router, prefix="/api/v1")
    app.include_router(obligations.router, prefix="/api/v1")
    app.include_router(instruments.router, prefix="/api/v1")
    app.include_router(documents.router, prefix="/api/v1")
    app.include_router(ocr.router, prefix="/api/v1")
    app.include_router(reconciliation.router, prefix="/api/v1")
    app.include_router(policy.router, prefix="/api/v1")
    app.include_router(findings.router, prefix="/api/v1")
    app.include_router(cases.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")

    @app.get("/api/v1/health", tags=["health"], include_in_schema=False)
    async def health_check():
        return {"status": "ok", "service": "fdr-sentinel"}

    return app


app = create_app()