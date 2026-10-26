"""Authentication service business logic."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.logging import get_logger
from app.core.security import create_refresh_token, create_session_token, generate_csrf_token, verify_password, verify_refresh_token
from app.crud.user import user as user_crud
from app.models.user import User

logger = get_logger("app.services.auth_service")


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def authenticate(self, email: str, password: str) -> User:
        db_user = user_crud.get_by_email(self.db, email=email)
        if not db_user or not verify_password(password, db_user.password_hash):
            logger.warning("auth.failed", extra={"action": "login", "target_type": "user", "target_id": email})
            raise AuthenticationError("Invalid email or password")
        if not db_user.is_active:
            raise AuthenticationError("Account is inactive")
        db_user.last_login_at = datetime.now(timezone.utc)
        self.db.add(db_user)
        self.db.commit()
        logger.info("auth.success", extra={"action": "login", "user_id": db_user.id, "target_type": "user", "target_id": db_user.id})
        return db_user

    def create_session(self, user: User) -> dict:
        session_token = create_session_token(user.id)
        refresh_token = create_refresh_token(user.id)
        csrf_token = generate_csrf_token()
        return {
            "session_token": session_token,
            "refresh_token": refresh_token,
            "csrf_token": csrf_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "institution_id": user.institution_id,
            },
        }

    def refresh_session(self, refresh_token: str) -> dict:
        user_id = verify_refresh_token(refresh_token)
        if not user_id:
            raise AuthenticationError("Invalid or expired refresh token")
        db_user = user_crud.get(self.db, user_id)
        if not db_user or not db_user.is_active:
            raise AuthenticationError("User not found or inactive")
        session_token = create_session_token(db_user.id)
        csrf_token = generate_csrf_token()
        return {
            "session_token": session_token,
            "csrf_token": csrf_token,
            "user": {
                "id": db_user.id,
                "email": db_user.email,
                "full_name": db_user.full_name,
                "role": db_user.role,
                "institution_id": db_user.institution_id,
            },
        }


def require_permission(current_user: User, permission: str) -> None:
    """Raise AuthorizationError if current_user lacks permission."""
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


def require_institution_access(current_user: User, institution_id: str | None) -> None:
    """Institution users may only access their own institution's records."""
    if current_user.role in ("aictc_admin", "aictc_reviewing_officer", "security_audit_reviewer"):
        return
    if current_user.institution_id is None or current_user.institution_id != institution_id:
        raise AuthorizationError("Cannot access records outside your institution")