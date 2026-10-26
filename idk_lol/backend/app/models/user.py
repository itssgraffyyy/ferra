"""User, role and permission models."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from enum import Enum as PyEnum

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin


class RoleName(str, PyEnum):
    INSTITUTION_USER = "institution_user"
    AICTE_REVIEWING_OFFICER = "aictc_reviewing_officer"
    AICTE_ADMIN = "aictc_admin"
    SECURITY_AUDIT_REVIEWER = "security_audit_reviewer"


class Permission(str, PyEnum):
    INSTITUTION_READ = "institution:read"
    INSTITUTION_WRITE = "institution:write"
    INSTITUTION_READ_ALL = "institution:read_all"
    OBLIGATION_READ = "obligation:read"
    OBLIGATION_WRITE = "obligation:write"
    INSTRUMENT_READ = "instrument:read"
    INSTRUMENT_WRITE = "instrument:write"
    INSTRUMENT_READ_ALL = "instrument:read_all"
    DOCUMENT_READ = "document:read"
    DOCUMENT_WRITE = "document:write"
    DOCUMENT_READ_ALL = "document:read_all"
    OCR_READ = "ocr:read"
    OCR_TRIGGER = "ocr:trigger"
    EVIDENCE_READ = "evidence:read"
    RECONCILIATION_READ = "reconciliation:read"
    POLICY_READ = "policy:read"
    FINDING_READ = "finding:read"
    FINDING_WRITE = "finding:write"
    CASE_READ = "case:read"
    CASE_WRITE = "case:write"
    CASE_READ_ALL = "case:read_all"
    AUDIT_READ = "audit:read"
    USER_MANAGE = "user:manage"
    SYSTEM_ADMIN = "system:admin"
ROLE_PERMISSIONS: dict[RoleName, List[Permission]] = {
    RoleName.INSTITUTION_USER: [
        Permission.INSTITUTION_READ,
        Permission.INSTITUTION_WRITE,
        Permission.OBLIGATION_READ,
        Permission.OBLIGATION_WRITE,
        Permission.INSTRUMENT_READ,
        Permission.INSTRUMENT_WRITE,
        Permission.DOCUMENT_READ,
        Permission.DOCUMENT_WRITE,
        Permission.OCR_READ,
        Permission.OCR_TRIGGER,
        Permission.EVIDENCE_READ,
        Permission.RECONCILIATION_READ,
        Permission.POLICY_READ,
        Permission.FINDING_READ,
        Permission.AUDIT_READ,
    ],
    RoleName.AICTE_REVIEWING_OFFICER: [
        Permission.INSTITUTION_READ_ALL,
        Permission.OBLIGATION_READ,
        Permission.INSTRUMENT_READ_ALL,
        Permission.DOCUMENT_READ_ALL,
        Permission.OCR_READ,
        Permission.OCR_TRIGGER,
        Permission.EVIDENCE_READ,
        Permission.RECONCILIATION_READ,
        Permission.POLICY_READ,
        Permission.FINDING_READ,
        Permission.FINDING_WRITE,
        Permission.CASE_READ,
        Permission.CASE_WRITE,
        Permission.AUDIT_READ,
    ],
    RoleName.AICTE_ADMIN: [
        Permission.INSTITUTION_READ_ALL,
        Permission.INSTITUTION_WRITE,
        Permission.OBLIGATION_READ,
        Permission.OBLIGATION_WRITE,
        Permission.INSTRUMENT_READ_ALL,
        Permission.DOCUMENT_READ_ALL,
        Permission.OCR_READ,
        Permission.EVIDENCE_READ,
        Permission.RECONCILIATION_READ,
        Permission.POLICY_READ,
        Permission.FINDING_READ,
        Permission.FINDING_WRITE,
        Permission.CASE_READ_ALL,
        Permission.CASE_WRITE,
        Permission.AUDIT_READ,
        Permission.USER_MANAGE,
    ],
    RoleName.SECURITY_AUDIT_REVIEWER: [
        Permission.INSTITUTION_READ_ALL,
        Permission.INSTRUMENT_READ_ALL,
        Permission.DOCUMENT_READ_ALL,
        Permission.OCR_READ,
        Permission.EVIDENCE_READ,
        Permission.RECONCILIATION_READ,
        Permission.POLICY_READ,
        Permission.FINDING_READ,
        Permission.CASE_READ_ALL,
        Permission.AUDIT_READ,
    ],
}


class Role(Base, IdMixin, TimestampMixin):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="role")


class PermissionModel(Base, IdMixin, TimestampMixin):
    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class UserRole(Base, IdMixin, TimestampMixin):
    __tablename__ = "user_roles"

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)

    user: Mapped["User"] = relationship(back_populates="user_roles")
    role: Mapped[Role] = relationship(back_populates="user_roles")


class RolePermission(Base, IdMixin):
    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    permission_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)


class User(Base, IdMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    institution_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("institutions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    institution: Mapped[Optional["Institution"]] = relationship(back_populates="users")
    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="user")

    def has_permission(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS.get(RoleName(self.role), [])