"""Authentication endpoints: login, refresh, me, logout, csrf token."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.exceptions import AuthenticationError
from app.core.logging import get_logger
from app.core.security import create_session_token, create_refresh_token, generate_csrf_token, verify_password
from app.crud.user import user as user_crud
from app.services.auth_service import AuthService
from app.schemas.auth import LoginRequest, LoginResponse, RefreshRequest
from app.api.deps import get_db, get_current_user, settings

logger = get_logger("app.api.endpoints.auth")

router = APIRouter(tags=["auth"])


def _set_session_cookies(response: Response, session_token: str, csrf_token: str, settings) -> None:
    secure = settings.COOKIE_SECURE
    samesite = settings.COOKIE_SAMESITE
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=secure,
        samesite=samesite,
        path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


def _clear_session_cookies(response: Response, settings) -> None:
    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")


@router.post("/auth/login", status_code=status.HTTP_200_OK)
def login(request: Request, response: Response, login_in: LoginRequest, db=Depends(get_db)):
    service = AuthService(db)
    user = service.authenticate(login_in.email, login_in.password)
    session = service.create_session(user)
    _set_session_cookies(response, session["session_token"], session["csrf_token"], settings)
    logger.info("auth.login", extra={"action": "login", "user_id": user.id})
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": session["session_token"],
            "token_type": "bearer",
            "csrf_token": session["csrf_token"],
            "user": session["user"],
        },
    )


@router.post("/auth/refresh", status_code=status.HTTP_200_OK)
def refresh(request: Request, response: Response, refresh_in: RefreshRequest, db=Depends(get_db)):
    service = AuthService(db)
    session = service.refresh_session(refresh_in.refresh_token)
    _set_session_cookies(response, session["session_token"], session["csrf_token"], settings)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": session["session_token"],
            "token_type": "bearer",
            "csrf_token": session["csrf_token"],
            "user": session["user"],
        },
    )


@router.post("/auth/logout", status_code=status.HTTP_200_OK)
def logout(response: Response):
    _clear_session_cookies(response, settings)
    return {"message": "Logged out"}


@router.get("/auth/me", status_code=status.HTTP_200_OK)
def me(current_user=Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "institution_id": current_user.institution_id,
        "is_active": current_user.is_active,
    }


@router.get("/auth/csrf-token", status_code=status.HTTP_200_OK)
def csrf_token():
    return {"csrf_token": generate_csrf_token()}