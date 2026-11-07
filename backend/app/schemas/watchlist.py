"""
Pydantic schemas for Domain Watchlist.
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class WatchlistCreate(BaseModel):
    domain: str = Field(..., description="Domain to monitor (e.g. example.com)")
    alert_types: Optional[List[str]] = Field(
        default=["cert_expiry", "new_report", "risk_score_change"],
        description="Event types that trigger alerts",
    )


class WatchlistResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    domain: str
    alert_types: Optional[List[str]] = None
    last_checked_at: Optional[datetime] = None
    last_risk_score: Optional[int] = None
    last_verdict: Optional[str] = None
    cert_days_left: Optional[int] = None
    is_active: bool
    created_at: datetime
    unread_alerts_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class WatchlistListResponse(BaseModel):
    total: int
    items: List[WatchlistResponse]

