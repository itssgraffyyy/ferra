"""Security primitives: password hashing, session tokens, CSRF tokens.

- Passwords are hashed with bcrypt via passlib.
- Session tokens are signed, time-expiring tokens (itsdangerous) carried in
  HttpOnly SameSite cookies.
- CSRF uses a double-submit pattern: a CSRF token cookie plus a matching
  X-CSRF-Token header on state-changing requests.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from passlib.context import CryptContext

from app.core.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _serializer() -> URLSafeTimedSerializer:
    settings = get_settings()
    return URLSafeTimedSerializer(settings.SECRET_KEY, salt="fdr-sentinel-session")


def create_session_token(user_id: str, expires_minutes: int | None = None) -> str:
    settings = get_settings()
    s = _serializer()
    return s.dumps({"sub": str(user_id)}, expires_in=expires_minutes * 60 if expires_minutes else None)


def verify_session_token(token: str) -> str | None:
    """Return user_id if token is valid and not expired, else None."""
    try:
        settings = get_settings()
        s = URLSafeTimedSerializer(settings.SECRET_KEY, salt="fdr-sentinel-session")
        max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        data = s.loads(token, max_age=max_age)
        return str(data.get("sub"))
    except (SignatureExpired, BadSignature, Exception):
        return None


def create_refresh_token(user_id: str) -> str:
    settings = get_settings()
    s = URLSafeTimedSerializer(settings.SECRET_KEY, salt="fdr-sentinel-refresh")
    max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    return s.dumps({"sub": str(user_id)}, expires_in=max_age)


def verify_refresh_token(token: str) -> str | None:
    try:
        settings = get_settings()
        s = URLSafeTimedSerializer(settings.SECRET_KEY, salt="fdr-sentinel-refresh")
        max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
        data = s.loads(token, max_age=max_age)
        return str(data.get("sub"))
    except (SignatureExpired, BadSignature, Exception):
        return None


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_compare(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return secrets.compare_digest(a, b)