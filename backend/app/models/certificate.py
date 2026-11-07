import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDField, JSONField

if TYPE_CHECKING:
    from app.models.scan import Scan


class Certificate(Base):
    """
    X.509 Certificate and Certificate Authority (CA) trust path assessment.
    """
    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        ForeignKey("scans.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    subject: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    issuer: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    valid_from: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    valid_to: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    days_until_expiry: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    is_valid: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    chain_valid: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    ct_log_present: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    ca_trust_status: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    raw_certificate: Mapped[Optional[Dict[str, Any]]] = mapped_column(
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
        back_populates="certificate",
    )

    def __repr__(self) -> str:
        return f"<Certificate id={self.id} subject={self.subject} is_valid={self.is_valid}>"

