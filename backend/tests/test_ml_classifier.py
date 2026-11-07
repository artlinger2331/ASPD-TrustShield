"""
Unit and integration tests for ML URL Classifier.
"""

import uuid
import pytest
from app.analyzers.ml_classifier import (
    calculate_shannon_entropy,
    extract_url_features,
    classify_url,
    save_ml_classification_to_db_sync,
)
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory


def test_shannon_entropy():
    """Verify entropy calculations for simple vs high-randomness strings."""
    zero_entropy = calculate_shannon_entropy("aaaaaa")
    assert zero_entropy == 0.0

    normal_entropy = calculate_shannon_entropy("example.com")
    assert 2.0 <= normal_entropy <= 3.5

    # High randomness DGA string
    dga_entropy = calculate_shannon_entropy("x7z9q2w1klm9p4t8.top")
    assert dga_entropy >= 3.8


def test_benign_url_classification():
    """Verify that official and simple domains receive low risk scores and safe verdict."""
    res = classify_url("https://www.google.com/search?q=trustshield")
    assert res.is_phishing is False
    assert res.risk_score <= 25
    assert res.verdict in ("safe", "low_risk")


def test_phishing_brand_lure_url():
    """Verify that brand mimicry on suspicious TLD with auth keywords is flagged dangerous."""
    res = classify_url("http://paypal-account-verification-support.top/login")
    assert res.is_phishing is True
    assert res.risk_score >= 65
    assert res.verdict in ("suspicious", "dangerous")
    indicator_names = [ind.feature_name for ind in res.top_indicators]
    assert "abused_tld" in indicator_names
    assert "brand_security_lure" in indicator_names or "security_keyword_density" in indicator_names


def test_ip_address_hostname():
    """Verify raw IP address as hostname triggers strong warning."""
    res = classify_url("http://192.168.1.50/banking/signin")
    assert res.features["is_ip_address"] is True
    assert res.risk_score >= 40
    indicator_names = [ind.feature_name for ind in res.top_indicators]
    assert "ip_as_host" in indicator_names


def test_at_symbol_obfuscation():
    """Verify @ symbol in URL is flagged."""
    res = classify_url("https://legit-site.com@attacker-site.com/auth")
    assert res.features["at_count"] > 0
    indicator_names = [ind.feature_name for ind in res.top_indicators]
    assert "at_symbol_in_url" in indicator_names


def test_ml_classification_database_persistence():
    """Verify that high-risk ML classification is persisted to scan_findings."""
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="http://apple-id-verify-alert.xyz/update",
            normalized_url="http://apple-id-verify-alert.xyz/update",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        res = classify_url("http://apple-id-verify-alert.xyz/update")
        finding = save_ml_classification_to_db_sync(scan.id, res, session)

        assert finding is not None
        assert finding.category == "ml_classifier"
        assert finding.severity in ("high", "critical")
        assert "ML Phishing Classifier" in finding.title
        assert finding.evidence["phishing_probability"] > 0.5
    finally:
        session.close()
