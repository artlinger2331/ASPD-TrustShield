import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional
from sqlalchemy import String, Float, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField, JSONField

if TYPE_CHECKING:
    from app.models.scan import Scan


class ThreatIntelResult(Base):
    """
    Threat intelligence findings from Google Safe Browsing, URLhaus, VirusTotal, and PhishTank.
    """
    __tablename__ = "threat_intel_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    match_type: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    confidence: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONField,
        nullable=True,
        default=dict,
    )
    raw_response: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONField,
        nullable=True,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="threat_intel_results",
    )

    __table_args__ = (
        Index("ix_threat_intel_scan_source", "scan_id", "source"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelResult id={self.id} source={self.source} match={self.match_type}>"

