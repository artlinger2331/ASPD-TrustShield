"""
Pydantic Schemas for Dashboard Security Metrics and Threat Telemetry Aggregation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict


class ThreatDistribution(BaseModel):
    phishing: int = 0
    malware: int = 0
    scam: int = 0
    suspicious_certs: int = 0
    header_vulnerabilities: int = 0


class DailyTrendPoint(BaseModel):
    date: str
    scans: int
    threats: int
    avg_score: float


class DashboardStatsResponse(BaseModel):
    total_scans: int
    malicious_detected: int
    suspicious_detected: int
    safe_detected: int
    clean_percentage: float
    avg_risk_score: float
    active_monitors_count: int
    threat_distribution: ThreatDistribution
    chart_trends: List[DailyTrendPoint]
    threat_types: List[Dict[str, Any]] = []
    cert_issues: List[Dict[str, Any]] = []
    risk_distribution: List[Dict[str, Any]] = []
    community_reports_count: int = 0
    total_findings: int = 0

    model_config = ConfigDict(from_attributes=True)

