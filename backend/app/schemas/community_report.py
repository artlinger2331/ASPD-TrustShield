"""
Pydantic schemas for Community Threat Reporting and Voting.
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class CommunityReportCreate(BaseModel):
    url: str = Field(..., description="Target malicious URL or domain")
    threat_type: str = Field(..., description="phishing, scam, malware, fake_recruitment, payment_fraud, impersonation")
    description: str = Field(..., min_length=10, description="Description of deceptive activity, lure or payload")
    screenshot_url: Optional[str] = None


class CommunityReportVote(BaseModel):
    vote_type: str = Field(..., description="confirm or false_positive")


class CommunityReportResponse(BaseModel):
    id: uuid.UUID
    url: str
    domain: str
    threat_type: str
    description: str
    screenshot_url: Optional[str] = None
    source: str
    status: str
    confirmations: int
    false_positive_votes: int
    created_at: datetime
    reporter_id: Optional[uuid.UUID] = None

    model_config = ConfigDict(from_attributes=True)


class CommunityReportListResponse(BaseModel):
    total: int
    items: List[CommunityReportResponse]

