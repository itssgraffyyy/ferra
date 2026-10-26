"""CSRF defense middleware (double-submit cookie pattern).

State-changing methods (POST/PUT/PATCH/DELETE) require a matching
X-CSRF-Token header and csrf cookie, except for auth login endpoints.
"""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError
from app.core.security import constant_time_compare

settings = get_settings()

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_EXEMPT_PATHS = {"/api/v1/auth/login", "/api/v1/auth/csrf-token", "/api/v1/health"}


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in STATE_CHANGING and not any(
            request.url.path.startswith(p) for p in CSRF_EXEMPT_PATHS
        ):
            cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME, "")
            header_token = request.headers.get("x-csrf-token", "")
            if not cookie_token or not header_token:
                raise AuthenticationError("CSRF token missing")
            if not constant_time_compare(cookie_token, header_token):
                raise AuthenticationError("CSRF token mismatch")
        response = await call_next(request)
        return response