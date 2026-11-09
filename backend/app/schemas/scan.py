"""
Pydantic v2 schemas for URL Scans, Findings, and Telemetry Reports.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# SCAN CREATION & BASIC STATUS
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    """
    Request payload to initiate a website security scan.
    """
    url: str = Field(..., min_length=1, max_length=2048, description="Target website URL to scan")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com"
            }
        }
    )


class ScanResponse(BaseModel):
    """
    Immediate acknowledgment upon creating a scan record.
    """
    id: uuid.UUID
    input_url: str
    normalized_url: str
    status: str
    current_step: Optional[int] = 0
    current_action: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanStatusResponse(BaseModel):
    """
    Polling response for the frontend progress stepper.
    """
    id: uuid.UUID
    status: str = Field(..., description="queued, running, completed, failed, timeout")
    step: int = Field(0, description="Current pipeline step (0 to 6)")
    total_steps: int = Field(6, description="Total pipeline steps")
    current_action: Optional[str] = Field(None, description="Active telemetry analysis description")
    verdict: Optional[str] = None
    risk_score: Optional[int] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None
    recommendation: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# DETAILED FINDINGS & TELEMETRY
# ---------------------------------------------------------------------------

class ScanFindingResponse(BaseModel):
    """
    Individual evidence-backed security or phishing finding.
    """
    id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    category: str = Field(..., description="credential_harvesting, brand_impersonation, tls_certificate, etc.")
    title: str
    severity: str = Field(..., description="info, low, medium, high, critical")
    confidence: Optional[float] = None
    description: str
    evidence: Optional[Dict[str, Any]] = None
    recommendation: Optional[str] = None
    risk_points: int = 0
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class CertificateReportResponse(BaseModel):
    """
    X.509 TLS certificate summary and CA trust path.
    """
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_valid: bool = False
    is_revoked: bool = False
    chain_valid: bool = False
    ct_log_present: bool = False
    ca_trust_status: Optional[str] = None
    raw_certificate: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class ThreatIntelReportResponse(BaseModel):
    """
    External threat feed telemetry match.
    """
    source: str
    match_type: Optional[str] = None
    confidence: Optional[float] = None
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class ScanReportResponse(BaseModel):
    """
    Consolidated report schema consuming all telemetry layers for UI rendering.
    """
    id: uuid.UUID
    input_url: str
    normalized_url: str
    final_url: Optional[str] = None
    status: str
    verdict: Optional[str] = None
    verdict_label: Optional[str] = None
    risk_score: Optional[int] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None
    recommendation: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    dns_records: Optional[Dict[str, Any]] = None
    security_headers: Optional[Dict[str, Any]] = None
    findings: List[ScanFindingResponse] = []
    certificate: Optional[CertificateReportResponse] = None
    threat_intel: List[ThreatIntelReportResponse] = []
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ScanListItem(BaseModel):
    """
    Compact scan item for recent scans tables and history lists.
    """
    id: uuid.UUID
    input_url: str
    normalized_url: str
    status: str
    verdict: Optional[str] = None
    risk_score: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    """
    Paginated envelope for scan listings.
    """
    total: int
    items: List[ScanListItem]

    model_config = ConfigDict(from_attributes=True)


