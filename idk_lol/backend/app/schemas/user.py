"""User schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    role: str = Field(min_length=1, max_length=50)
    institution_id: str | None = None
    is_active: bool = True


class UserCreate(UserBase):
    password: str = Field(min_length=8)


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    institution_id: str | None = None
    is_active: bool | None = None
    password: str | None = None


class UserRead(UserBase):
    id: str
    last_login_at: str | None = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"