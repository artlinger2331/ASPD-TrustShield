import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, List, Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField, JSONField, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.alert import Alert


class WatchlistItem(Base, TimestampMixin):
    """
    User-monitored domains tracked for cert expiry, new reports, or score changes.
    """
    __tablename__ = "watchlist_items"

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
    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    alert_types: Mapped[Optional[List[str]]] = mapped_column(
        JSONField,
        nullable=True,
        default=lambda: ["cert_expiry", "new_report", "risk_score_change"],
    )
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        index=True,
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="watchlist_items",
    )
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert",
        back_populates="watchlist_item",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        UniqueConstraint("user_id", "domain", name="uq_user_watchlist_domain"),
        Index("ix_watchlist_user_active", "user_id", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<WatchlistItem id={self.id} domain={self.domain} active={self.is_active}>"
