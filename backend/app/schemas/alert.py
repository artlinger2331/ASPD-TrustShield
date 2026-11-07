"""
Pydantic schemas for Security Alerts.
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class AlertResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    watchlist_item_id: Optional[uuid.UUID] = None
    alert_type: str = Field(..., description="cert_expiry, new_report, risk_score_change, threat_detection")
    message: str
    is_read: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    unread_count: int
    total: int
    items: List[AlertResponse]
