import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import DateTime, JSON, Uuid
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models in TrustShield.
    """
    pass


# Dialect-aware JSON column: uses native binary JSONB on PostgreSQL, standard JSON elsewhere
JSONField = JSON().with_variant(JSONB, "postgresql")

# Universal UUID type across PostgreSQL (native UUID) and SQLite/other backends
UUIDField = Uuid(as_uuid=True)


class TimestampMixin:
    """
    Standard UTC audit timestamp mixin for models.
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
