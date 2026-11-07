import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import String, Text, Integer, Float, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.scan_finding import ScanFinding
    from app.models.certificate import Certificate
    from app.models.threat_intel import ThreatIntelResult


class Scan(Base, TimestampMixin):
    """
    Website security scan tracking overall risk score, verdict, and pipeline status.
    """
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUIDField,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    input_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    normalized_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )
    final_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="queued",
        index=True,
        nullable=False,
    )
    verdict: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )
    risk_score: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    confidence: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    recommendation: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="scans",
    )
    findings: Mapped[List["ScanFinding"]] = relationship(
        "ScanFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )
    certificate: Mapped[Optional["Certificate"]] = relationship(
        "Certificate",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="select",
    )
    threat_intel_results: Mapped[List["ThreatIntelResult"]] = relationship(
        "ThreatIntelResult",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_status_created", "status", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status} verdict={self.verdict} score={self.risk_score}>"
