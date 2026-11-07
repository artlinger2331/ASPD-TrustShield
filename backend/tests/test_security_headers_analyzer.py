"""
Unit tests for Web Security Headers and Passive Configuration Analyzer.
"""

import pytest

from app.analyzers.security_headers_analyzer import (
    analyze_security_headers,
    save_security_headers_findings_to_db_sync,
)
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory


def test_hardened_security_headers():
    """Verify that a fully hardened server achieves Grade A+ with zero risk points."""
    hardened_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
        "Server": "Cloudflare",
    }
    raw_cookies = [
        "session=abc12345; Secure; HttpOnly; SameSite=Strict; Path=/",
    ]

    result = analyze_security_headers(
        headers=hardened_headers,
        target_url="https://secure-bank.com",
        cookies_raw=raw_cookies,
        is_https=True,
    )

    assert result.security_grade == "A+"
    assert result.hsts_present is True
    assert result.csp_present is True
    assert result.x_frame_options_present is True
    assert result.x_content_type_options_present is True
    assert result.total_risk_points == 0
    assert len(result.findings) == 0

    # Ensure all frontend headers evaluated are marked "pass"
    for h in result.headers_evaluated:
        assert h.status == "pass"

    assert len(result.cookies_evaluated) == 1
    assert result.cookies_evaluated[0].is_safe is True


def test_missing_security_headers_vulnerabilities():
    """Verify that missing defense headers (HSTS, CSP, XFO, XCTO) produce categorized findings."""
    empty_headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Date": "Fri, 07 Nov 2026 08:00:00 GMT",
    }

    result = analyze_security_headers(
        headers=empty_headers,
        target_url="https://vulnerable-site.com",
        is_https=True,
    )

    assert result.security_grade in ("D", "F")
    assert result.hsts_present is False
    assert result.csp_present is False
    assert result.x_frame_options_present is False
    assert result.x_content_type_options_present is False

    finding_titles = [f.title for f in result.findings]
    assert any("HSTS" in title for title in finding_titles)
    assert any("Content-Security-Policy" in title for title in finding_titles)
    assert any("X-Frame-Options" in title for title in finding_titles)
    assert any("X-Content-Type-Options" in title for title in finding_titles)
    assert result.total_risk_points >= 30

    # Verify matching status items for frontend
    header_status_map = {h.name: h.status for h in result.headers_evaluated}
    assert header_status_map["HSTS"] == "fail"
    assert header_status_map["Content Security Policy"] == "fail"
    assert header_status_map["X-Frame-Options"] == "fail"
    assert header_status_map["X-Content-Type-Options"] == "fail"


def test_permissive_csp_and_short_hsts():
    """Verify that permissive directives ('unsafe-eval') and short HSTS durations produce warnings."""
    headers = {
        "Strict-Transport-Security": "max-age=86400",  # Only 1 day
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
    }

    result = analyze_security_headers(
        headers=headers,
        target_url="https://example.org",
        is_https=True,
    )

    header_status_map = {h.name: h.status for h in result.headers_evaluated}
    assert header_status_map["HSTS"] == "warn"
    assert header_status_map["Content Security Policy"] == "warn"
    assert header_status_map["X-Frame-Options"] == "pass"
    assert header_status_map["X-Content-Type-Options"] == "pass"

    assert any("Permissive Content Security Policy" in f.title for f in result.findings)


def test_insecure_cookie_attributes():
    """Verify that cookies missing Secure and HttpOnly flags trigger findings."""
    headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    raw_cookies = [
        "user_auth=secret_token_12345; Path=/; Domain=test.com",  # Missing Secure and HttpOnly
    ]

    result = analyze_security_headers(
        headers=headers,
        target_url="https://insecure-cookies.com",
        cookies_raw=raw_cookies,
        is_https=True,
    )

    assert len(result.cookies_evaluated) == 1
    cookie = result.cookies_evaluated[0]
    assert cookie.has_secure is False
    assert cookie.has_httponly is False
    assert cookie.is_safe is False

    finding_titles = [f.title for f in result.findings]
    assert any("Missing 'Secure' Flag" in title for title in finding_titles)
    assert any("Missing 'HttpOnly' Flag" in title for title in finding_titles)


def test_server_information_disclosure():
    """Verify that explicit server and technology versions are flagged."""
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "X-AspNet-Version": "4.0.30319",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }

    result = analyze_security_headers(
        headers=headers,
        target_url="https://disclosing-server.com",
        is_https=True,
    )

    assert result.server_disclosure == "Apache/2.4.41 (Ubuntu)"
    assert len(result.technology_disclosures) >= 3
    assert any("Information Disclosure" in f.title for f in result.findings)


def test_security_headers_database_persistence():
    """Verify end-to-end database persistence of security header findings."""
    session = local_session_factory()
    try:
        # 1. Create a Scan record
        scan = Scan(
            input_url="https://unhardened-portal.com",
            normalized_url="https://unhardened-portal.com",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # 2. Analyze weak headers
        weak_headers = {
            "Server": "Apache/2.2.14",
        }
        result = analyze_security_headers(
            headers=weak_headers,
            target_url="https://unhardened-portal.com",
            is_https=True,
        )

        assert len(result.findings) >= 3

        # 3. Persist to database
        saved_findings = save_security_headers_findings_to_db_sync(
            scan_id=scan.id,
            findings=result.findings,
            db=session,
        )

        assert len(saved_findings) == len(result.findings)

        # Query database directly
        db_findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        assert len(db_findings) == len(result.findings)
        for f in db_findings:
            assert f.scan_id == scan.id
            assert f.category == "security_headers"
            assert f.risk_points > 0
    finally:
        session.close()

