"""Audit logging middleware: logs sensitive requests/responses safely."""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.logging import get_logger

logger = get_logger("app.api.middleware.audit")

SENSITIVE_PATHS = ("/api/v1/auth/login", "/api/v1/documents", "/api/v1/instruments")


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in SENSITIVE_PATHS) and request.method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            logger.info(
                "api.sensitive_request",
                extra={
                    "action": "audit_request",
                    "method": request.method,
                    "path": path,
                    "client": request.client.host if request.client else None,
                },
            )
        return await call_next(request)