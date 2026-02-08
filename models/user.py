"""User database models"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    Integer,
    SmallInteger,
    String,
)
from sqlalchemy.orm import Mapped, MappedColumn, relationship

if TYPE_CHECKING:
    from models.devlog import Devlog
    from models.user_project import UserProject

from models.base import Base


class User(Base):
    """User table"""

    # TODO: i don't know what we need but i sure as hell know we need more than ts
    # TODO: dm hana about ts question mark? idk.

    __tablename__ = "users"

    id: Mapped[int] = MappedColumn(
        Integer, autoincrement=True, primary_key=True, unique=True
    )
    email: Mapped[str] = MappedColumn(String, nullable=False, unique=True)
    permissions: Mapped[list[int]] = MappedColumn(
        ARRAY(SmallInteger), nullable=False, server_default="{}"
    )
    hackatime_id: Mapped[int | None] = MappedColumn(
        Integer, nullable=True, unique=True, default=None
    )
    username: Mapped[str | None] = MappedColumn(
        String, nullable=True, unique=True, default=None
    )
    slack_id: Mapped[str | None] = MappedColumn(
        String, nullable=True, unique=True, default=None
    )
    idv_status: Mapped[str | None] = MappedColumn(
        String, nullable=True, unique=False, default=None
    )
    ysws_eligible: Mapped[bool | None] = MappedColumn(
        Boolean, nullable=True, unique=False, default=None
    )
    projects: Mapped[list["UserProject"]] = relationship(
        "UserProject", back_populates="user", cascade="all, delete-orphan"
    )
    devlogs: Mapped[list["Devlog"]] = relationship(
        "Devlog", back_populates="user", cascade="all, delete-orphan"
    )
    marked_for_deletion: Mapped[bool] = MappedColumn(
        Boolean, nullable=False, default=False
    )
    date_for_deletion: Mapped[datetime | None] = MappedColumn(
        DateTime(timezone=True), nullable=True, default=None
    )
    hackatime_last_fetched: Mapped[datetime] = MappedColumn(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    cards_balance: Mapped[int] = MappedColumn(
        Integer,
        nullable=False,
        default=0,
    )
    referral_code_used: Mapped[str | None] = MappedColumn(
        String(64), nullable=True, default=None
    )
