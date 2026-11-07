"""
Pydantic v2 schemas for Domain and DNS Infrastructure telemetry.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.content_analysis import ContentFindingSchema


class SPFSummary(BaseModel):
    """
    SPF (Sender Policy Framework) email authentication summary.
    """
    has_spf: bool = False
    raw_record: Optional[str] = None
    is_permissive: bool = False  # e.g. uses '+all' or '?all'
    mechanism_all: Optional[str] = None  # ~all, -all, ?all, +all
    details: Optional[str] = None


class DMARCSummary(BaseModel):
    """
    DMARC (Domain-based Message Authentication) policy summary.
    """
    has_dmarc: bool = False
    raw_record: Optional[str] = None
    policy: Optional[str] = None  # 'none', 'quarantine', 'reject'
    is_enforced: bool = False     # True if policy is quarantine or reject
    details: Optional[str] = None


class EmailSecuritySummary(BaseModel):
    """
    Consolidated email spoofing defense posture (SPF, DMARC, MX).
    """
    has_mx: bool = False
    mx_servers: List[str] = []
    spf: SPFSummary = Field(default_factory=SPFSummary)
    dmarc: DMARCSummary = Field(default_factory=DMARCSummary)
    spoofing_risk_level: str = "none"  # none, low, medium, high


class DomainAgeSummary(BaseModel):
    """
    Domain age and registration information.
    """
    creation_date: Optional[datetime] = None
    age_days: Optional[int] = None
    is_newly_registered: bool = False
    registrar: Optional[str] = None


class DomainAnalysisResult(BaseModel):
    """
    Consolidated telemetry for Domain and DNS infrastructure analysis.
    """
    domain: str
    base_domain: str
    tld: str
    is_suspicious_tld: bool = False
    is_ddns_or_shortener: bool = False
    dns_records: Dict[str, List[str]] = Field(default_factory=dict)
    name_servers: List[str] = []
    ip_addresses: List[str] = []
    email_security: EmailSecuritySummary = Field(default_factory=EmailSecuritySummary)
    domain_age: Optional[DomainAgeSummary] = None
    total_risk_points: int = 0
    max_severity: str = "info"
    summary: str = ""
    findings: List[ContentFindingSchema] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
