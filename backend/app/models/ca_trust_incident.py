import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDField


class CATrustIncident(Base):
    """
    Catalog of Certificate Authority (CA) trust incidents, distrusted roots,
    compromised intermediate authorities, and weak key-generation incidents.
    """
    __tablename__ = "ca_trust_incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUIDField,
        primary_key=True,
        default=uuid.uuid4,
    )
    ca_name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
    )
    incident_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="distrusted, revoked, misissuance, surveillance_ties, weak_key",
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        default="high",
        nullable=False,
        doc="critical, high, medium, low",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    advisory_url: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<CATrustIncident id={self.id} ca_name={self.ca_name} incident_type={self.incident_type}>"
