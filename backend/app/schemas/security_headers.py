"""
Pydantic v2 schemas for Web Security Headers and Passive Security Assessment.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.content_analysis import ContentFindingSchema


class WebSecurityCheckItem(BaseModel):
    """
    Standardized result for each passive security check.
    Fulfills exact user requirements:
    - Check name
    - Status: Pass, Warning, Fail, or Not Applicable
    - Severity: critical, high, medium, low, info
    - Evidence: technical forensic dictionary
    - Plain-language explanation
    - Remediation advice
    - Risk points
    """
    check_name: str
    status: str = Field(..., description="Pass, Warning, Fail, or Not Applicable")
    severity: str = Field(default="info", description="critical, high, medium, low, info")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    remediation: str
    risk_points: int = 0


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
    Consolidated web security headers, cookie flags, mixed content,
    and exposed paths telemetry.
    """
    https_enforced: bool = False
    http_to_https_redirect: bool = False
    hsts_present: bool = False
    csp_present: bool = False
    x_frame_options_present: bool = False
    x_content_type_options_present: bool = False
    referrer_policy_present: bool = False
    permissions_policy_present: bool = False
    mixed_content_detected: bool = False
    exposed_paths_detected: List[str] = Field(default_factory=list)
    security_grade: str = "C"  # A+, A, B, C, D, F
    checks: List[WebSecurityCheckItem] = Field(default_factory=list)
    headers_evaluated: List[SecurityHeaderItem] = Field(default_factory=list)
    cookies_evaluated: List[CookieSecurityItem] = Field(default_factory=list)
    server_disclosure: Optional[str] = None
    technology_disclosures: List[str] = Field(default_factory=list)
    findings: List[ContentFindingSchema] = Field(default_factory=list)
    total_risk_points: int = 0
    max_severity: str = "info"
    summary: str = ""

    model_config = ConfigDict(from_attributes=True)
