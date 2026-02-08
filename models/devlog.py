"""User database models"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, MappedColumn, relationship

if TYPE_CHECKING:
    from models.user import User
    from models.user_project import UserProject

from models.base import Base


class Devlog(Base):
    """Devlog posts"""

    __tablename__ = "devlogs"

    id: Mapped[int] = MappedColumn(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = MappedColumn(Integer, ForeignKey("users.id"), nullable=False)
    project_id: Mapped[int] = MappedColumn(
        Integer, ForeignKey("projects.id"), nullable=False
    )
    content: Mapped[str] = MappedColumn(Text, nullable=False)
    media_url: Mapped[str] = MappedColumn(Text, nullable=False)
    created_at: Mapped[datetime] = MappedColumn(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime | None] = MappedColumn(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        onupdate=lambda: datetime.now(UTC),
    )
    hours_snapshot: Mapped[float] = MappedColumn(Float, nullable=False)
    cards_awarded: Mapped[int] = MappedColumn(Integer, nullable=False, default=0)
    state: Mapped[str] = MappedColumn(String, nullable=False, default=0)

    # Relationship back to user
    user: Mapped["User"] = relationship("User", back_populates="devlogs")
    project: Mapped["UserProject"] = relationship(
        "UserProject", back_populates="devlogs"
    )
