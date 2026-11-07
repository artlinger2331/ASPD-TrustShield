"""
Pydantic schemas for Threat Intelligence feeds and aggregation.
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class ThreatIntelMatch(BaseModel):
    source: str = Field(..., description="Provider name: google_safe_browsing, urlhaus, virustotal, phishtank")
    match_type: Optional[str] = Field(None, description="MALWARE, SOCIAL_ENGINEERING, PHISHING, MALICIOUS, CLEAN")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_malicious: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_response: Dict[str, Any] = Field(default_factory=dict)


class ThreatIntelAnalysisResult(BaseModel):
    url: str
    is_flagged: bool = False
    matches: List[ThreatIntelMatch] = Field(default_factory=list)
    malicious_count: int = 0
    clean_count: int = 0
    highest_confidence: float = 0.0
    summary: str = "No threat intelligence records matched."
