import uuid
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import String, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField, TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.community_report import CommunityReport
    from app.models.watchlist import WatchlistItem
    from app.models.alert import Alert


class User(Base, TimestampMixin):
    """
    User accounts, credential hashing, and Role-Based Access Control (RBAC).
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    full_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        default="user",
        index=True,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    community_reports: Mapped[List["CommunityReport"]] = relationship(
        "CommunityReport",
        back_populates="reporter",
        lazy="select",
    )
    watchlist_items: Mapped[List["WatchlistItem"]] = relationship(
        "WatchlistItem",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<User email={self.email} role={self.role}>"

