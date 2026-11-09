"""
Unit tests for Passive Web Security Assessment in TrustShield.
Covers all 11 passive checks, content signature verification,
standardized result items, and database persistence.
"""

import pytest
from app.services.web_security_analyzer import (
    analyze_web_security,
    save_web_security_findings_to_db_sync,
    verify_env_content,
    verify_git_config_content,
    verify_zip_content,
    verify_admin_content,
)
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory


# ---------------------------------------------------------------------------
# FIXTURES & HELPERS
# ---------------------------------------------------------------------------

def _get_check_by_name(result, name: str):
    """Helper to retrieve a specific WebSecurityCheckItem by check_name."""
    for c in result.checks:
        if c.check_name.lower() == name.lower():
            return c
    return None


# ---------------------------------------------------------------------------
# TEST CASES: 11 INDIVIDUAL CHECKS
# ---------------------------------------------------------------------------

def test_http_to_https_redirect_permanent():
    """Verify HTTP 301/308 permanent redirect to HTTPS is graded Pass."""
    result = analyze_web_security(
        target_url="https://bank.com",
        headers={"Server": "nginx"},
        http_redirect_status=301,
        http_redirect_target="https://bank.com/",
        is_https=True,
    )
    check = _get_check_by_name(result, "HTTP to HTTPS Redirect")
    assert check is not None
    assert check.status == "Pass"
    assert check.risk_points == 0
    assert "permanently redirects" in check.explanation


def test_http_to_https_redirect_temporary_warning():
    """Verify HTTP 302/307 temporary redirect to HTTPS receives Warning."""
    result = analyze_web_security(
        target_url="https://bank.com",
        headers={"Server": "nginx"},
        http_redirect_status=302,
        http_redirect_target="https://bank.com/",
        is_https=True,
    )
    check = _get_check_by_name(result, "HTTP to HTTPS Redirect")
    assert check is not None
    assert check.status == "Warning"
    assert check.risk_points == 5


def test_http_to_https_missing_plain_http_fail():
    """Verify serving traffic over plain HTTP without HTTPS redirect fails with high severity."""
    result = analyze_web_security(
        target_url="http://insecure-site.com",
        headers={"Server": "Apache"},
        http_redirect_status=200,
        is_https=False,
    )
    check = _get_check_by_name(result, "HTTP to HTTPS Redirect")
    assert check is not None
    assert check.status == "Fail"
    assert check.severity == "high"
    assert check.risk_points >= 20
    assert any("Missing HTTP to HTTPS Redirection" in f.title for f in result.findings)


def test_hsts_pass_warn_fail():
    """Verify HSTS check behaves correctly across strong, weak, and missing configurations."""
    # 1. Pass: strong max-age (1 year)
    res_pass = analyze_web_security(
        target_url="https://safe.com",
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
        is_https=True,
    )
    c_pass = _get_check_by_name(res_pass, "Strict-Transport-Security")
    assert c_pass.status == "Pass"

    # 2. Warning: short max-age (1 day)
    res_warn = analyze_web_security(
        target_url="https://safe.com",
        headers={"Strict-Transport-Security": "max-age=86400"},
        is_https=True,
    )
    c_warn = _get_check_by_name(res_warn, "Strict-Transport-Security")
    assert c_warn.status == "Warning"

    # 3. Fail: missing HSTS on HTTPS
    res_fail = analyze_web_security(
        target_url="https://safe.com",
        headers={},
        is_https=True,
    )
    c_fail = _get_check_by_name(res_fail, "Strict-Transport-Security")
    assert c_fail.status == "Fail"


def test_csp_pass_warn_fail():
    """Verify Content-Security-Policy evaluation for strict, permissive, and missing headers."""
    # 1. Pass: strict CSP
    res_pass = analyze_web_security(
        target_url="https://safe.com",
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'"},
        is_https=True,
    )
    c_pass = _get_check_by_name(res_pass, "Content-Security-Policy")
    assert c_pass.status == "Pass"

    # 2. Warning: permissive with unsafe-inline / unsafe-eval
    res_warn = analyze_web_security(
        target_url="https://safe.com",
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"},
        is_https=True,
    )
    c_warn = _get_check_by_name(res_warn, "Content-Security-Policy")
    assert c_warn.status == "Warning"

    # 3. Fail: missing CSP
    res_fail = analyze_web_security(
        target_url="https://safe.com",
        headers={},
        is_https=True,
    )
    c_fail = _get_check_by_name(res_fail, "Content-Security-Policy")
    assert c_fail.status == "Fail"


def test_x_frame_options():
    """Verify X-Frame-Options evaluation."""
    res_deny = analyze_web_security("https://site.com", {"X-Frame-Options": "DENY"}, is_https=True)
    assert _get_check_by_name(res_deny, "X-Frame-Options").status == "Pass"

    res_same = analyze_web_security("https://site.com", {"X-Frame-Options": "SAMEORIGIN"}, is_https=True)
    assert _get_check_by_name(res_same, "X-Frame-Options").status == "Pass"

    res_missing = analyze_web_security("https://site.com", {}, is_https=True)
    assert _get_check_by_name(res_missing, "X-Frame-Options").status == "Fail"


def test_x_content_type_options():
    """Verify X-Content-Type-Options nosniff."""
    res_pass = analyze_web_security("https://site.com", {"X-Content-Type-Options": "nosniff"}, is_https=True)
    assert _get_check_by_name(res_pass, "X-Content-Type-Options").status == "Pass"

    res_fail = analyze_web_security("https://site.com", {}, is_https=True)
    assert _get_check_by_name(res_fail, "X-Content-Type-Options").status == "Fail"


def test_referrer_policy():
    """Verify Referrer-Policy."""
    res_pass = analyze_web_security("https://site.com", {"Referrer-Policy": "strict-origin-when-cross-origin"}, is_https=True)
    assert _get_check_by_name(res_pass, "Referrer-Policy").status == "Pass"

    res_warn = analyze_web_security("https://site.com", {"Referrer-Policy": "unsafe-url"}, is_https=True)
    assert _get_check_by_name(res_warn, "Referrer-Policy").status == "Warning"


def test_permissions_policy():
    """Verify Permissions-Policy."""
    res_pass = analyze_web_security("https://site.com", {"Permissions-Policy": "geolocation=(), camera=()"}, is_https=True)
    assert _get_check_by_name(res_pass, "Permissions-Policy").status == "Pass"

    res_missing = analyze_web_security("https://site.com", {}, is_https=True)
    assert _get_check_by_name(res_missing, "Permissions-Policy").status == "Warning"


def test_cookie_flags_security():
    """Verify cookie security flags (Secure, HttpOnly, SameSite)."""
    # 1. Hardened cookie -> Pass
    res_pass = analyze_web_security(
        target_url="https://site.com",
        headers={},
        cookies_raw=["auth_token=secret123; Secure; HttpOnly; SameSite=Strict; Path=/"],
        is_https=True,
    )
    c_pass = _get_check_by_name(res_pass, "Cookie Security Flags")
    assert c_pass.status == "Pass"

    # 2. Insecure cookie missing Secure and HttpOnly -> Fail
    res_fail = analyze_web_security(
        target_url="https://site.com",
        headers={},
        cookies_raw=["session_id=12345; Path=/"],
        is_https=True,
    )
    c_fail = _get_check_by_name(res_fail, "Cookie Security Flags")
    assert c_fail.status == "Fail"
    assert any("Missing 'Secure' Flag" in f.title for f in res_fail.findings)
    assert any("Missing 'HttpOnly' Flag" in f.title for f in res_fail.findings)


def test_mixed_content_detection():
    """Verify active and passive mixed content detection in HTML."""
    # 1. Active mixed content (script over http)
    active_html = """
    <html>
      <head><script src="http://cdn.attacker.com/tracking.js"></script></head>
      <body><h1>Secure Store</h1></body>
    </html>
    """
    res_active = analyze_web_security(
        target_url="https://secure-store.com",
        headers={},
        html_content=active_html,
        is_https=True,
    )
    c_active = _get_check_by_name(res_active, "Mixed Content")
    assert c_active.status == "Fail"
    assert c_active.severity == "high"
    assert any("Active Mixed Content Detected" in f.title for f in res_active.findings)

    # 2. Passive mixed content (image over http)
    passive_html = """
    <html>
      <body><img src="http://cdn.images.com/banner.jpg" alt="Banner" /></body>
    </html>
    """
    res_passive = analyze_web_security(
        target_url="https://secure-store.com",
        headers={},
        html_content=passive_html,
        is_https=True,
    )
    c_passive = _get_check_by_name(res_passive, "Mixed Content")
    assert c_passive.status == "Warning"
    assert c_passive.severity == "medium"

    # 3. Clean page
    clean_html = """
    <html>
      <head><script src="https://cdn.secure.com/app.js"></script></head>
      <body><img src="https://images.com/logo.png" /></body>
    </html>
    """
    res_clean = analyze_web_security(
        target_url="https://secure-store.com",
        headers={},
        html_content=clean_html,
        is_https=True,
    )
    c_clean = _get_check_by_name(res_clean, "Mixed Content")
    assert c_clean.status == "Pass"


def test_server_version_disclosure():
    """Verify server and framework version disclosure in response headers."""
    # Discloses specific version numbers
    res_leak = analyze_web_security(
        target_url="https://site.com",
        headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
        is_https=True,
    )
    c_leak = _get_check_by_name(res_leak, "Server Version Disclosure")
    assert c_leak.status == "Warning"
    assert any("Server Technology & Version Information Disclosure" in f.title for f in res_leak.findings)

    # Obfuscated / generic banner
    res_safe = analyze_web_security(
        target_url="https://site.com",
        headers={"Server": "cloudflare"},
        is_https=True,
    )
    c_safe = _get_check_by_name(res_safe, "Server Version Disclosure")
    assert c_safe.status == "Pass"


def test_exposed_paths_env_file():
    """Verify exposed /.env file triggers Critical finding when verified with content signature."""
    probes = {
        "/.env": {
            "status_code": 200,
            "body": "APP_ENV=production\nAPP_KEY=base64:s0m3s3cr3tk3y=\nDB_PASSWORD=supersecret",
            "headers": {"content-type": "text/plain"},
        }
    }
    result = analyze_web_security(
        target_url="https://vulnerable.com",
        headers={},
        exposed_path_probes=probes,
        is_https=True,
    )
    c_exposed = _get_check_by_name(result, "Common Exposed Sensitive Paths")
    assert c_exposed.status == "Fail"
    assert c_exposed.severity == "critical"
    assert "/.env" in result.exposed_paths_detected
    assert any("Exposed Environment Configuration File" in f.title for f in result.findings)


def test_exposed_paths_git_config():
    """Verify exposed /.git/config file triggers Critical finding."""
    probes = {
        "/.git/config": {
            "status_code": 200,
            "body": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = git@github.com:org/repo.git",
            "headers": {"content-type": "text/plain"},
        }
    }
    result = analyze_web_security(
        target_url="https://vulnerable.com",
        headers={},
        exposed_path_probes=probes,
        is_https=True,
    )
    assert "/.git/config" in result.exposed_paths_detected
    assert any("Git Repository Metadata" in f.title for f in result.findings)


def test_exposed_paths_backup_zip():
    """Verify exposed /backup.zip archive triggers Critical finding."""
    probes = {
        "/backup.zip": {
            "status_code": 200,
            "body_bytes": b"PK\x03\x04\x14\x00\x00\x00mock-zip-content",
            "headers": {"content-type": "application/zip"},
        }
    }
    result = analyze_web_security(
        target_url="https://vulnerable.com",
        headers={},
        exposed_path_probes=probes,
        is_https=True,
    )
    assert "/backup.zip" in result.exposed_paths_detected
    assert any("Backup Archive" in f.title for f in result.findings)


def test_exposed_paths_admin_portal():
    """Verify exposed /admin portal triggers Warning finding."""
    probes = {
        "/admin": {
            "status_code": 200,
            "body": "<html><body><h1>Admin Control Panel</h1><form><input name='username'/><input type='password'/></form></body></html>",
            "headers": {"content-type": "text/html"},
        }
    }
    result = analyze_web_security(
        target_url="https://vulnerable.com",
        headers={},
        exposed_path_probes=probes,
        is_https=True,
    )
    assert "/admin" in result.exposed_paths_detected
    assert any("Administrative Portal (/admin)" in f.title for f in result.findings)


def test_exposed_paths_spa_false_positive_prevention():
    """Verify SPA returning 200 OK with HTML on 404s does NOT trigger .env or backup.zip finding."""
    spa_index_html = "<!doctype html><html><head><title>React App</title></head><body><div id='root'></div></body></html>"
    probes = {
        "/.env": {"status_code": 200, "body": spa_index_html, "headers": {"content-type": "text/html"}},
        "/.git/config": {"status_code": 200, "body": spa_index_html, "headers": {"content-type": "text/html"}},
        "/backup.zip": {"status_code": 200, "body": spa_index_html, "body_bytes": spa_index_html.encode(), "headers": {"content-type": "text/html"}},
    }
    result = analyze_web_security(
        target_url="https://react-spa.com",
        headers={},
        exposed_path_probes=probes,
        is_https=True,
    )
    assert len(result.exposed_paths_detected) == 0
    c_paths = _get_check_by_name(result, "Common Exposed Sensitive Paths")
    assert c_paths.status == "Pass"


def test_standardized_check_structure():
    """Verify all 11 checks adhere to user required schema fields."""
    result = analyze_web_security(
        target_url="https://example.com",
        headers={},
        is_https=True,
    )
    assert len(result.checks) == 11
    valid_statuses = {"Pass", "Warning", "Fail", "Not Applicable"}
    valid_severities = {"critical", "high", "medium", "low", "info"}

    for c in result.checks:
        assert isinstance(c.check_name, str) and len(c.check_name) > 0
        assert c.status in valid_statuses, f"Invalid status {c.status} on {c.check_name}"
        assert c.severity in valid_severities, f"Invalid severity {c.severity} on {c.check_name}"
        assert isinstance(c.evidence, dict)
        assert isinstance(c.explanation, str) and len(c.explanation) > 0
        assert isinstance(c.remediation, str) and len(c.remediation) > 0
        assert isinstance(c.risk_points, int) and c.risk_points >= 0


def test_database_persistence_of_web_security_findings():
    """Verify end-to-end database persistence of web security findings into scan_findings."""
    session = local_session_factory()
    try:
        # 1. Create a Scan
        scan = Scan(
            input_url="https://insecure-portal.com",
            normalized_url="https://insecure-portal.com",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # 2. Run analysis with weak headers and exposed path
        result = analyze_web_security(
            target_url="https://insecure-portal.com",
            headers={"Server": "nginx/1.14.0"},
            exposed_path_probes={
                "/.env": {
                    "status_code": 200,
                    "body": "APP_KEY=base64:xyz123\nDB_PASSWORD=secret",
                    "headers": {"content-type": "text/plain"},
                }
            },
            is_https=True,
        )
        assert len(result.findings) >= 3

        # 3. Save findings to DB
        saved = save_web_security_findings_to_db_sync(
            scan_id=scan.id,
            findings=result.findings,
            db=session,
        )
        assert len(saved) == len(result.findings)

        # Query database directly
        db_records = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        assert len(db_records) == len(result.findings)
        assert any(r.severity == "critical" for r in db_records)
        assert any("Environment Configuration File" in r.title for r in db_records)
    finally:
        session.close()

