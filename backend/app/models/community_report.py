import uuid
from typing import TYPE_CHECKING, Optional
from sqlalchemy import String, Text, Integer, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User


class CommunityReport(Base, TimestampMixin):
    """
    Crowdsourced phishing, scam, and malware threat reports from researchers and users.
    """
    __tablename__ = "community_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    reporter_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUIDField,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    threat_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    screenshot_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    source: Mapped[str] = mapped_column(
        String(32),
        default="community",
        index=True,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        index=True,
        nullable=False,
    )
    confirmations: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    false_positive_votes: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Relationships
    reporter: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="community_reports",
    )

    __table_args__ = (
        Index("ix_reports_domain_status", "domain", "status"),
        Index("ix_reports_threat_status", "threat_type", "status"),
    )

    def __repr__(self) -> str:
        return f"<CommunityReport id={self.id} domain={self.domain} threat={self.threat_type} status={self.status}>"
