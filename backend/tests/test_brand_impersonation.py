"""
Unit and integration tests for Brand Impersonation & Typosquatting Analyzer.
"""

import uuid
import pytest
from app.analyzers.brand_impersonation import (
    levenshtein_distance,
    jaro_winkler_similarity,
    normalize_homoglyphs,
    analyze_brand_impersonation,
    save_brand_impersonation_findings_to_db_sync,
)
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory


def test_levenshtein_and_jaro_winkler():
    """Verify string distance metric accuracy."""
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("netflix", "metflix") == 1
    assert levenshtein_distance("google", "google") == 0

    sim = jaro_winkler_similarity("paypal", "paypai")
    assert sim >= 0.85


def test_homoglyph_detection():
    """Verify Cyrillic homoglyph lookalikes are detected."""
    # Using Cyrillic 'а' (\u0430) and 'р' (\u0440)
    cyrillic_paypal = "\u0440\u0430ypal.top"
    matches = analyze_brand_impersonation(cyrillic_paypal)
    assert len(matches) > 0
    homoglyph_match = next((m for m in matches if m.technique == "homoglyph_replacement"), None)
    assert homoglyph_match is not None
    assert homoglyph_match.brand_name == "paypal"
    assert homoglyph_match.severity == "critical"


def test_combosquatting_detection():
    """Verify brand + security lure combinations trigger combosquatting alerts."""
    matches = analyze_brand_impersonation("https://chase-bank-verify-account.com/auth")
    assert len(matches) > 0
    combo_match = next((m for m in matches if m.technique == "combosquatting"), None)
    assert combo_match is not None
    assert combo_match.brand_name == "chase"
    assert combo_match.severity == "high"


def test_subdomain_spoofing_detection():
    """Verify embedding brand name into subdomain of foreign domain is caught."""
    matches = analyze_brand_impersonation("https://apple.com.secure-cloud-portal.xyz/login")
    assert len(matches) > 0
    sub_match = next((m for m in matches if m.technique == "subdomain_spoofing"), None)
    assert sub_match is not None
    assert sub_match.brand_name == "apple"
    assert sub_match.severity == "critical"


def test_legitimate_official_domains_ignored():
    """Verify official brand domains do not trigger self-impersonation alerts."""
    assert len(analyze_brand_impersonation("https://www.paypal.com/signin")) == 0
    assert len(analyze_brand_impersonation("https://accounts.google.com/login")) == 0
    assert len(analyze_brand_impersonation("https://netflix.com/browse")) == 0


def test_brand_impersonation_database_persistence():
    """Verify findings are stored in scan_findings table with proper metadata."""
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="https://wellsfargo-secure-auth.xyz",
            normalized_url="https://wellsfargo-secure-auth.xyz",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        matches = analyze_brand_impersonation("https://wellsfargo-secure-auth.xyz")
        findings = save_brand_impersonation_findings_to_db_sync(scan.id, matches, session)

        assert len(findings) > 0
        assert findings[0].category == "brand_impersonation"
        assert findings[0].risk_points >= 40
        assert "WELLSFARGO" in findings[0].title
    finally:
        session.close()

