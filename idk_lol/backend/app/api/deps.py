"""API dependencies: database session, current user, authorization."""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.logging import get_logger
from app.core.security import verify_session_token
from app.crud.user import user as user_crud
from app.db.session import get_db
from app.models.user import User

logger = get_logger("app.api.deps")

# oauth2_scheme kept for OpenAPI docs (bearer), but we use session cookies primarily.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

settings = get_settings()


def get_request_id(request: Request) -> str:
    return request.headers.get("x-request-id", "")


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None),
) -> User:
    """Resolve the current authenticated user from the session cookie or Bearer token.

    Session token is expected in a cookie named SESSION_COOKIE_NAME.
    A Bearer token is also accepted (for API clients).
    """
    token: Optional[str] = None
    # Prefer cookie
    cookie_name = settings.SESSION_COOKIE_NAME
    cookie_token = request.cookies.get(cookie_name)
    if cookie_token:
        token = cookie_token
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]

    if not token:
        logger.warning("auth.missing_token", extra={"action": "authenticate"})
        raise AuthenticationError("Authentication required")

    user_id = verify_session_token(token)
    if not user_id:
        logger.warning("auth.invalid_token", extra={"action": "authenticate"})
        raise AuthenticationError("Invalid or expired session")

    db_user = user_crud.get(db, user_id)
    if not db_user or not db_user.is_active:
        raise AuthenticationError("User not found or inactive")
    return db_user


def require_permission(permission: str):
    """Dependency factory: require a specific permission."""

    def checker(current_user: User = Depends(get_current_user)) -> User:
        if not current_user.has_permission(permission):  # type: ignore[attr-defined]
            logger.warning(
                "authz.denied",
                extra={
                    "action": "require_permission",
                    "user_id": current_user.id,
                    "target_type": "permission",
                    "target_id": permission,
                },
            )
            raise AuthorizationError(f"Missing required permission: {permission}")
        return current_user

    return checker


def require_institution_access(institution_id_param: str = "institution_id"):
    """Dependency factory: institution users only access their own institution."""

    def checker(
        current_user: User = Depends(get_current_user),
        institution_id: Optional[str] = None,
    ) -> User:
        if current_user.role in (
            "aictc_admin",
            "aictc_reviewing_officer",
            "security_audit_reviewer",
        ):
            return current_user
        # For institution users, resolve institution_id from path/query if provided
        target = institution_id or current_user.institution_id
        if current_user.institution_id is None or target != current_user.institution_id:
            raise AuthorizationError("Cannot access records outside your institution")
        return current_user

    return checker