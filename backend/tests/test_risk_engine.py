"""
Unit tests for the Upgraded Explainable Risk & Trust-Score Engine.

Tests all 8 security telemetry layers:
1. URL and domain analysis
2. Redirect analysis
3. Phishing-content analysis
4. Certificate and CA trust analysis
5. Web-security assessment
6. Threat-intelligence results
7. ML URL classification
8. Community reports

Verifies:
- Normal / safe websites
- High-risk phishing portals
- Exact schema output structure
- Suspicious websites
- Conflicting signals (e.g. valid EV SSL on brand phishing page)
- Missing, failed, or low-confidence signals
- Bounded signal rules (no single signal controls the result)
"""

import uuid
from app.services.risk_engine import evaluate_risk
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.models.community_report import CommunityReport
from app.schemas.ml_classification import MLClassificationResult, MLFeatureContribution
from app.schemas.url_analysis import RedirectHop


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
    assert result.confidence >= 0.85
    assert len(result.top_reasons) >= 2
    assert "url_domain" in result.category_scores
    assert "phishing_content" in result.category_scores
    assert "certificate_trust" in result.category_scores
    assert "web_security" in result.category_scores
    assert "threat_intelligence" in result.category_scores
    assert result.category_scores["phishing_content"] == 0
    assert result.category_scores["threat_intelligence"] == 0
    assert result.category_scores["certificate_trust"] == 0


def test_risk_engine_high_risk_phishing_portal():
    """Verify evaluation for a severe banking impersonation credential harvesting portal."""
    findings = [
        ScanFinding(
            category="brand_impersonation",
            title="Domain impersonates a known bank",
            severity="critical",
            risk_points=18,
        ),
        ScanFinding(
            category="credential_harvesting",
            title="Page requests password and OTP",
            severity="critical",
            risk_points=28,
        ),
        ScanFinding(
            category="domain_infrastructure",
            title="Domain was registered recently",
            severity="high",
            risk_points=14,
        ),
        ScanFinding(
            category="tls_certificate",
            title="Untrusted self-signed certificate",
            severity="high",
            risk_points=10,
        ),
        ScanFinding(
            category="security_headers",
            title="Missing HSTS and CSP defense headers",
            severity="medium",
            risk_points=8,
        ),
    ]

    threat_intel = [
        ThreatIntelResult(
            source="google_safe_browsing",
            match_type="SOCIAL_ENGINEERING",
            confidence=0.95,
        ),
    ]

    result = evaluate_risk(
        findings=findings,
        certificate=None,
        threat_intel_results=threat_intel,
    )

    assert result.verdict in ("high_risk", "dangerous")
    assert result.risk_score >= 80
    assert result.confidence >= 0.80
    assert len(result.top_reasons) >= 3
    assert any("bank" in r.lower() or "password" in r.lower() for r in result.top_reasons)
    assert result.category_scores["phishing_content"] >= 20
    assert result.category_scores["threat_intelligence"] >= 10
    assert result.category_scores["url_domain"] >= 15


def test_risk_engine_exact_schema_output():
    """Verify output contract matches the required JSON structure."""
    findings = [
        ScanFinding(
            category="brand_impersonation",
            title="Domain impersonates a known bank",
            severity="critical",
            risk_points=18,
        ),
        ScanFinding(
            category="domain_infrastructure",
            title="Domain was registered recently",
            severity="high",
            risk_points=14,
        ),
        ScanFinding(
            category="credential_harvesting",
            title="Page requests password and OTP",
            severity="critical",
            risk_points=28,
        ),
        ScanFinding(
            category="tls_certificate",
            title="Untrusted CA certificate",
            severity="high",
            risk_points=10,
        ),
        ScanFinding(
            category="security_headers",
            title="Insecure HTTP transmission",
            severity="medium",
            risk_points=8,
        ),
    ]

    threat_intel = [
        ThreatIntelResult(
            source="urlhaus",
            match_type="MALWARE",
            confidence=0.9,
        ),
    ]

    result = evaluate_risk(
        findings=findings,
        threat_intel_results=threat_intel,
    )

    # Validate all fields present and correctly typed
    assert isinstance(result.risk_score, int)
    assert 0 <= result.risk_score <= 100
    assert result.verdict in ("safe", "low_risk", "suspicious", "high_risk", "dangerous")
    assert isinstance(result.confidence, float)
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.summary, str) and len(result.summary) > 0
    assert isinstance(result.recommendation, str) and len(result.recommendation) > 0
    assert isinstance(result.top_reasons, list)
    assert len(result.top_reasons) > 0
    assert isinstance(result.category_scores, dict)
    assert set(result.category_scores.keys()) == {
        "url_domain",
        "phishing_content",
        "certificate_trust",
        "web_security",
        "threat_intelligence",
    }
    assert isinstance(result.evidence, list)


def test_risk_engine_suspicious_website():
    """Verify suspicious website with redirection hops and lookalike domain without active malware."""
    findings = [
        ScanFinding(
            category="url_heuristics",
            title="High entropy domain lookalike",
            severity="medium",
            risk_points=15,
        ),
        ScanFinding(
            category="security_headers",
            title="Missing Content-Security-Policy",
            severity="low",
            risk_points=5,
        ),
    ]

    redirect_hops = [
        RedirectHop(hop_number=1, from_url="https://tracker.com/r", to_url="https://hop2.com/in", status_code=302),
        RedirectHop(hop_number=2, from_url="https://hop2.com/in", to_url="https://target.com/home", status_code=301),
    ]

    result = evaluate_risk(
        findings=findings,
        redirect_hops=redirect_hops,
    )

    assert result.verdict in ("suspicious", "low_risk")
    assert 20 <= result.risk_score < 70
    assert result.category_scores["phishing_content"] == 0
    assert result.category_scores["threat_intelligence"] == 0
    assert result.category_scores["url_domain"] > 0


def test_risk_engine_conflicting_signals_ev_cert_on_phishing():
    """Verify that a valid EV certificate does NOT suppress or hide a credential harvesting form."""
    valid_ev_cert = Certificate(
        subject="CN=chase-verify-billing.com",
        issuer="CN=DigiCert Global Root CA",
        is_valid=True,
        ca_trust_status="trusted",
        ct_log_present=True,
    )

    findings = [
        ScanFinding(
            category="credential_harvesting",
            title="Credential harvester requesting online banking credentials",
            severity="critical",
            risk_points=30,
        ),
        ScanFinding(
            category="brand_impersonation",
            title="Chase Bank Logo and Deceptive Styling",
            severity="critical",
            risk_points=15,
        ),
    ]

    result = evaluate_risk(
        findings=findings,
        certificate=valid_ev_cert,
    )

    # The valid TLS certificate produces 0 certificate risk points
    assert result.category_scores["certificate_trust"] == 0
    # But phishing content is dangerous and correctly attributed
    assert result.category_scores["phishing_content"] >= 25
    # The overall verdict is high risk because credential harvesting is detected
    assert result.verdict in ("high_risk", "dangerous")
    assert result.risk_score >= 45


def test_risk_engine_missing_or_failed_telemetry_resilience():
    """Verify engine handles missing optional inputs gracefully without errors or NaN."""
    result = evaluate_risk(
        findings=[],
        certificate=None,
        threat_intel_results=None,
        ml_result=None,
        domain=None,
        redirect_hops=None,
        community_reports=None,
    )

    assert result.verdict == "safe"
    assert result.risk_score == 0
    assert 0.50 <= result.confidence <= 0.99
    assert result.category_scores == {
        "url_domain": 0,
        "phishing_content": 0,
        "certificate_trust": 0,
        "web_security": 0,
        "threat_intelligence": 0,
    }
    assert isinstance(result.top_reasons, list)
    assert isinstance(result.evidence, list)


def test_risk_engine_bounded_influence_security_header():
    """Verify that minor missing security headers cannot unilaterally flag a site as dangerous."""
    findings = [
        ScanFinding(
            category="security_headers",
            title="Missing HSTS Header",
            severity="low",
            risk_points=3,
        ),
        ScanFinding(
            category="security_headers",
            title="Missing X-Frame-Options",
            severity="low",
            risk_points=3,
        ),
    ]

    result = evaluate_risk(findings=findings)
    assert result.risk_score <= 10
    assert result.category_scores["web_security"] <= 10
    assert result.verdict == "safe"


def test_risk_engine_bounded_influence_threat_intel():
    """Verify threat intelligence feed match is capped and transparently attributed."""
    threat_intel = [
        ThreatIntelResult(
            source="phishtank",
            match_type="PHISHING",
            confidence=0.9,
        ),
    ]

    result = evaluate_risk(
        findings=[],
        threat_intel_results=threat_intel,
    )

    # Threat intel category is bounded at 25 points maximum
    assert result.category_scores["threat_intelligence"] <= 25
    assert result.category_scores["threat_intelligence"] >= 10
    assert result.category_scores["phishing_content"] == 0
    assert result.risk_score <= 25


def test_risk_engine_redirect_analysis_signal():
    """Verify redirect analysis handles protocol downgrades and hop thresholds."""
    downgrade_hops = [
        RedirectHop(
            hop_number=1,
            from_url="https://secure.example.com",
            to_url="http://insecure.example.com/login",
            status_code=302,
        ),
        RedirectHop(
            hop_number=2,
            from_url="http://insecure.example.com/login",
            to_url="http://insecure.example.com/dest",
            status_code=301,
        ),
    ]

    result = evaluate_risk(
        findings=[],
        redirect_hops=downgrade_hops,
    )

    # 4 points for 2 hops + 10 points for protocol downgrade = 14 pts
    assert result.category_scores["url_domain"] >= 10
    assert any("protocol downgrade" in r.lower() or "https to unencrypted" in r.lower() for r in result.top_reasons)


def test_risk_engine_community_reports_signal():
    """Verify community reports contribute to threat intelligence category."""
    confirmed_report = CommunityReport(
        url="https://malicious-scam.com/auth",
        domain="malicious-scam.com",
        threat_type="phishing",
        description="Fake credential harvest portal reported by researcher",
        status="verified",
        confirmations=4,
        false_positive_votes=0,
    )

    result = evaluate_risk(
        findings=[],
        community_reports=[confirmed_report],
    )

    assert result.category_scores["threat_intelligence"] >= 8
    assert any("community" in r.lower() for r in result.top_reasons)


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
