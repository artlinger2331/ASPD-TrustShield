"""
Pydantic v2 schemas for SSL/TLS Certificate and CA Trust analysis.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.content_analysis import ContentFindingSchema


class CertificateChainNode(BaseModel):
    """
    Individual certificate node in the TLS trust path.
    """
    name: str
    type: str = Field(..., description="Root CA, Intermediate CA, or Website Certificate")
    status: str = Field(..., description="trusted, valid, untrusted, self_signed")


class CertificateAnalysisResult(BaseModel):
    """
    Consolidated TLS certificate, validation, and CA trust telemetry.
    """
    https: bool = False
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_valid: bool = False
    is_revoked: bool = False
    chain_valid: bool = False
    ct_log_present: bool = False
    ca_trust_status: str = "unknown"  # trusted, distrusted, self_signed, unknown
    weak_algo: bool = False
    san_matched: bool = False
    san_list: List[str] = Field(default_factory=list)
    chain: List[CertificateChainNode] = Field(default_factory=list)
    warning: Optional[str] = None
    raw_certificate: Dict[str, Any] = Field(default_factory=dict)
    findings: List[ContentFindingSchema] = Field(default_factory=list)
    total_risk_points: int = 0
    max_severity: str = "info"

    model_config = ConfigDict(from_attributes=True)

