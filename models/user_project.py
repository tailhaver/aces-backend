"""User database models"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, MappedColumn, relationship

if TYPE_CHECKING:
    from models.devlog import Devlog
    from models.user import User

from models.base import Base


class UserProject(Base):
    """User Project table"""

    __tablename__ = "projects"

    id: Mapped[int] = MappedColumn(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = MappedColumn(String, nullable=False)
    user_email: Mapped[str] = MappedColumn(
        String, ForeignKey("users.email"), nullable=False
    )
    hackatime_projects: Mapped[list[str]] = MappedColumn(
        JSON, nullable=False, default=list
    )
    hackatime_total_hours: Mapped[float] = MappedColumn(
        Float, nullable=False, default=0.0
    )
    last_updated: Mapped[datetime] = MappedColumn(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    repo: Mapped[str] = MappedColumn(String, nullable=True, default="")
    demo_url: Mapped[str] = MappedColumn(String, nullable=True, default="")
    preview_image: Mapped[str] = MappedColumn(String, nullable=True, default="")
    description: Mapped[str | None] = MappedColumn(Text, nullable=True, default=None)
    shipped: Mapped[bool] = MappedColumn(Boolean, nullable=False, default=False)
    devlogs: Mapped[list["Devlog"]] = relationship(
        "Devlog", back_populates="project", cascade="all, delete-orphan"
    )

    # Relationship back to user
    user: Mapped["User"] = relationship("User", back_populates="projects")
