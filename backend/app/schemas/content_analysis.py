import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ContentFindingSchema(BaseModel):
    category: str = Field(..., description="Category: phishing, forms, brand_impersonation, scripts, hidden_elements")
    title: str = Field(..., description="Descriptive headline of the finding")
    severity: str = Field(..., description="critical, high, medium, low, info")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    description: str = Field(..., description="Clear explanation of the detected threat indicator")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Concrete technical indicators and extracts")
    recommendation: Optional[str] = Field(default=None, description="Security advice for end users")
    risk_points: int = Field(default=0, ge=0, le=100)
    raw_data: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ContentAnalysisResult(BaseModel):
    url: str
    final_url: Optional[str] = None
    page_title: Optional[str] = None
    has_login_form: bool = False
    has_credential_harvesting: bool = False
    detected_brands: List[str] = Field(default_factory=list)
    brand_mismatches: List[str] = Field(default_factory=list)
    sensitive_fields: List[str] = Field(default_factory=list)
    suspicious_scripts: List[str] = Field(default_factory=list)
    hidden_inputs_count: int = 0
    phishing_keywords_found: List[str] = Field(default_factory=list)
    total_risk_points: int = 0
    max_severity: str = "info"
    summary: str = ""
    findings: List[ContentFindingSchema] = Field(default_factory=list)
    error_message: Optional[str] = None

