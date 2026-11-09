"""
Pydantic schemas for the Explainable Risk Engine.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class TelemetrySubscore(BaseModel):
    layer: str = Field(..., description="domain, certificate, headers, content, threat_intel, ml_classifier")
    display_name: str
    score: int = Field(..., ge=0, le=100, description="Risk sub-score from 0 (safest) to 100 (most dangerous)")
    status: str = Field(..., description="safe, warning, danger")
    findings_count: int = 0
    key_evidence: List[str] = Field(default_factory=list)


class RiskExplanation(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    verdict: str = Field(..., description="safe, low_risk, suspicious, high_risk, dangerous")
    verdict_label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    recommendation: str
    top_reasons: List[str] = Field(default_factory=list, description="Ranked human-readable key risk reasons or reassuring factors")
    category_scores: Dict[str, int] = Field(
        default_factory=dict,
        description="Category points breakdown: url_domain, phishing_content, certificate_trust, web_security, threat_intelligence",
    )
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Structured security evidence items")
    subscores: Dict[str, TelemetrySubscore] = Field(default_factory=dict)
    positive_factors: List[str] = Field(default_factory=list)
    negative_factors: List[str] = Field(default_factory=list)
