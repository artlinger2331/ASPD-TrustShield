"""
Pydantic schemas for ML URL Classification.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class MLFeatureContribution(BaseModel):
    feature_name: str
    feature_value: Any
    weight: float
    description: str


class MLClassificationResult(BaseModel):
    url: str
    is_phishing: bool
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    verdict: str = Field(..., description="safe, low_risk, suspicious, dangerous")
    shannon_entropy: float
    features: Dict[str, Any] = Field(default_factory=dict)
    top_indicators: List[MLFeatureContribution] = Field(default_factory=list)
    summary: str

