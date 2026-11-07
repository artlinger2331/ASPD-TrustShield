"""
Pydantic v2 schemas for Web Security Headers and Passive Configuration analysis.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.content_analysis import ContentFindingSchema


class SecurityHeaderItem(BaseModel):
    """
    Evaluation of a single HTTP security defense header.
    Format directly matches frontend badges and table displays.
    """
    name: str = Field(..., description="e.g. HSTS, Content Security Policy, X-Frame-Options")
    status: str = Field(..., description="'pass', 'fail', or 'warn'")
    detail: str = Field(..., description="Explainable description of the header status")
    value: Optional[str] = None


class CookieSecurityItem(BaseModel):
    """
    Evaluation of cookie security flags in Set-Cookie headers.
    """
    name: str
    has_secure: bool = False
    has_httponly: bool = False
    same_site: Optional[str] = None
    is_safe: bool = False
    detail: Optional[str] = None


class SecurityHeadersAnalysisResult(BaseModel):
    """
    Consolidated web security headers and passive configuration telemetry.
    """
    https_enforced: bool = False
    hsts_present: bool = False
    csp_present: bool = False
    x_frame_options_present: bool = False
    x_content_type_options_present: bool = False
    referrer_policy_present: bool = False
    permissions_policy_present: bool = False
    security_grade: str = "C"  # A+, A, B, C, D, F
    headers_evaluated: List[SecurityHeaderItem] = Field(default_factory=list)
    cookies_evaluated: List[CookieSecurityItem] = Field(default_factory=list)
    server_disclosure: Optional[str] = None
    technology_disclosures: List[str] = Field(default_factory=list)
    findings: List[ContentFindingSchema] = Field(default_factory=list)
    total_risk_points: int = 0
    max_severity: str = "info"
    summary: str = ""

    model_config = ConfigDict(from_attributes=True)

