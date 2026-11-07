"""
Unit tests for the Explainable Risk Engine.
"""

import uuid
from app.services.risk_engine import evaluate_risk
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.schemas.ml_classification import MLClassificationResult, MLFeatureContribution


def test_risk_engine_safe_website():
    """Verify evaluation for a completely clean website with valid TLS."""
    cert = Certificate(
        subject="CN=example.com",
        issuer="CN=DigiCert Global Root CA",
        is_valid=True,
        ca_trust_status="trusted",
        ct_log_present=True,
    )
    threat_intel = [
        ThreatIntelResult(source="google_safe_browsing", match_type="CLEAN"),
        ThreatIntelResult(source="urlhaus", match_type="CLEAN"),
    ]

    result = evaluate_risk(
        findings=[],
        certificate=cert,
        threat_intel_results=threat_intel,
        ml_result=None,
    )

    assert result.verdict == "safe"
    assert result.risk_score <= 15
    assert result.confidence >= 0.90
    assert len(result.positive_factors) >= 2
    assert len(result.negative_factors) == 0
    assert result.subscores["threat_intel"].score == 0
    assert result.subscores["certificate"].score == 0


def test_risk_engine_threat_intel_override():
    """Verify threat intelligence match triggers critical risk override."""
    threat_intel = [
        ThreatIntelResult(
            source="google_safe_browsing",
            match_type="SOCIAL_ENGINEERING",
        ),
    ]

    result = evaluate_risk(
        findings=[],
        certificate=None,
        threat_intel_results=threat_intel,
    )

    assert result.verdict == "dangerous"
    assert result.risk_score >= 90
    assert "google_safe_browsing" in result.summary


def test_risk_engine_phishing_content_override():
    """Verify that severe credential harvesting findings trigger dangerous verdict."""
    findings = [
        ScanFinding(
            category="credential_harvesting",
            title="Cross-Domain Password Submission Form",
            severity="critical",
            risk_points=50,
        ),
        ScanFinding(
            category="brand_impersonation",
            title="PayPal Brand Impersonation on Foreign Domain",
            severity="critical",
            risk_points=40,
        ),
    ]

    result = evaluate_risk(findings=findings)
    assert result.verdict == "dangerous"
    assert result.risk_score >= 80
    assert result.subscores["content"].status == "danger"


def test_risk_engine_subscore_breakdown():
    """Verify that all 6 telemetry layers generate valid subscores and statuses."""
    findings = [
        ScanFinding(
            category="domain_infrastructure",
            title="Suspicious TLD (.top)",
            severity="high",
            risk_points=25,
        ),
        ScanFinding(
            category="security_headers",
            title="Missing HSTS Header",
            severity="low",
            risk_points=10,
        ),
    ]

    result = evaluate_risk(findings=findings)
    assert "threat_intel" in result.subscores
    assert "content" in result.subscores
    assert "domain" in result.subscores
    assert "certificate" in result.subscores
    assert "headers" in result.subscores
    assert "ml_classifier" in result.subscores

    assert result.subscores["domain"].score == 25
    assert result.subscores["domain"].status == "safe"
    assert result.subscores["headers"].score == 10
