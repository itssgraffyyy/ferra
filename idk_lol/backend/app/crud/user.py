"""CRUD operations for users."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate


class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    def get_by_email(self, db: Session, *, email: str) -> User | None:
        return db.query(User).filter(User.email == email).first()

    def get_by_institution(self, db: Session, *, institution_id: str, skip: int = 0, limit: int = 100):
        return (
            db.query(User)
            .filter(User.institution_id == institution_id)
            .offset(skip)
            .limit(limit)
            .all()
        )


user = CRUDUser(User)