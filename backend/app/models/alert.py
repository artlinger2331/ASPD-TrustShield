import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from sqlalchemy import String, Text, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.watchlist import WatchlistItem


class Alert(Base):
    """
    Security alerts dispatched to users regarding watchlisted domains, certificates, or threats.
    """
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    watchlist_item_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUIDField,
        ForeignKey("watchlist_items.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    is_read: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        index=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="alerts",
    )
    watchlist_item: Mapped[Optional["WatchlistItem"]] = relationship(
        "WatchlistItem",
        back_populates="alerts",
    )

    __table_args__ = (
        Index("ix_alerts_user_read_created", "user_id", "is_read", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.id} type={self.alert_type} read={self.is_read}>"

