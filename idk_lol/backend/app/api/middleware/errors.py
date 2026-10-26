"""Global error handling middleware.

Returns consistent JSON error schemas without leaking sensitive data.
"""

from __future__ import annotations

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.exceptions import AppException
from app.core.logging import get_logger

logger = get_logger("app.api.middleware.errors")


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except AppException as exc:
            logger.warning(
                "app_exception",
                extra={
                    "action": "error_handler",
                    "code": exc.code,
                    "status_code": exc.status_code,
                    "message": exc.message,
                },
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "error": True,
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("unhandled_exception", extra={"action": "error_handler", "message": str(exc)})
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "code": "internal_server_error",
                    "message": "An unexpected error occurred",
                    "details": {},
                },
            )