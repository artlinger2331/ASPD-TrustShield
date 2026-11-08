"""
Unit and Integration Tests for TrustShield Phishing Content Detection Service.
Validates detection of:
1. Login forms and password fields.
2. OTP / 2FA fields.
3. Card, UPI, bank account, IFSC, Aadhaar, and PAN fields.
4. Phishing keywords and deceptive urgency lures.
5. Brand references and unauthorized domain mismatches.
6. Suspicious external scripts and concealed iframes.
7. Hidden form fields and evasion parameters.
8. Obfuscated JavaScript indicators (eval, unescape, right-click suppression).
9. Deceptive buttons and calls to action (CTAs).
10. Database persistence into scan_findings table.
"""

import os
import uuid
from pathlib import Path
import pytest

from app.services.content_analyzer import (
    analyze_html,
    is_safe_url,
    get_base_domain,
    save_findings_to_db_sync,
)
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory, local_sync_engine, Base


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "html"


def load_fixture(filename: str) -> str:
    path = FIXTURES_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(local_sync_engine)
    yield


def test_legitimate_login_page():
    """
    Legitimate login page on verified domain:
    Should detect login form and password input, but classify as informational/low risk
    with no brand mismatch or credential-harvesting flags.
    """
    html = load_fixture("legitimate_login.html")
    result = analyze_html(html, "https://developer.company.com/login")

    assert result.has_login_form is True
    assert result.has_credential_harvesting is False
    assert len(result.brand_mismatches) == 0
    assert result.total_risk_points <= 10
    assert result.max_severity in ("info", "low")

    # Verify structured finding format
    login_findings = [f for f in result.findings if f.evidence.get("detector_type") == "login_form"]
    assert len(login_findings) >= 1
    f = login_findings[0]
    assert f.category == "phishing"
    assert f.title == "Login form detected"
    assert f.severity == "info"
    assert f.confidence >= 0.80
    assert "email" in f.evidence.get("input_fields", []) or "password" in f.evidence.get("input_fields", [])
    assert f.risk_points == 5


def test_legitimate_ecommerce_page():
    """
    Legitimate e-commerce portal with search and newsletter:
    Should have zero login forms, zero credential harvesting, and zero risk points.
    """
    html = load_fixture("legitimate_ecommerce.html")
    result = analyze_html(html, "https://auroragear.com/products")

    assert result.has_login_form is False
    assert result.has_credential_harvesting is False
    assert len(result.sensitive_fields) == 0
    assert len(result.findings) == 0
    assert result.total_risk_points == 0
    assert result.max_severity == "info"


def test_phishing_credential_harvesting_page():
    """
    Deceptive PayPal clone on unauthorized domain (paypa1-security-update.xyz):
    Must detect:
    - Brand mismatch (PayPal on paypa1-security-update.xyz)
    - Credential harvesting form posting to external webhook (api.telegram.org)
    - Password and OTP input fields
    - Deceptive urgency keywords
    - Deceptive CTA button ('Unlock Account')
    - Suspicious hidden iframe and obfuscated JS (eval/unescape)
    - Excessive hidden fields
    """
    html = load_fixture("phishing_credential_harvesting.html")
    result = analyze_html(html, "https://paypa1-security-update.xyz/login")

    assert result.has_login_form is True
    assert result.has_credential_harvesting is True
    assert "PayPal" in result.brand_mismatches
    assert "OTP / 2FA" in result.sensitive_fields
    assert result.total_risk_points >= 75
    assert result.max_severity == "critical"

    # Verify brand mismatch finding
    brand_f = next(f for f in result.findings if f.evidence.get("detector_type") == "brand_mismatch")
    assert brand_f.category == "phishing"
    assert "PayPal" in brand_f.title
    assert brand_f.severity == "critical"
    assert brand_f.risk_points == 35

    # Verify credential-harvesting form finding
    harvest_f = next(f for f in result.findings if f.evidence.get("detector_type") == "credential_harvesting")
    assert harvest_f.category == "phishing"
    assert harvest_f.title == "Credential-harvesting form detected"
    assert harvest_f.severity in ("critical", "high")
    assert harvest_f.confidence >= 0.85
    assert "Do not enter credentials" in harvest_f.recommendation
    assert any("password" in inp for inp in harvest_f.evidence.get("input_fields", []))

    # Verify OTP field finding
    otp_f = next(f for f in result.findings if f.evidence.get("detector_type") == "otp_field")
    assert otp_f.category == "phishing"
    assert otp_f.severity == "high"
    assert otp_f.risk_points == 25

    # Verify deceptive CTA button
    cta_f = next(f for f in result.findings if f.evidence.get("detector_type") == "deceptive_cta")
    assert cta_f.category == "phishing"
    assert "Unlock Account" in cta_f.evidence.get("button_text", "")

    # Verify obfuscated JS indicator
    obf_f = next(f for f in result.findings if f.evidence.get("detector_type") == "obfuscated_js")
    assert obf_f.category == "phishing"

    # Verify hidden iframe
    iframe_f = next(f for f in result.findings if f.evidence.get("detector_type") == "suspicious_iframe")
    assert iframe_f.category == "phishing"
    assert iframe_f.severity == "high"


def test_phishing_indian_banking_kyc_page():
    """
    SBI NetBanking fake KYC phishing portal:
    Must detect:
    - Brand mismatch: State Bank of India claimed on unofficial domain
    - Bank account number and IFSC code solicitation
    - Aadhaar and PAN national identity solicitation
    - Payment card and CVV fields
    - OTP fields
    - Multi-vector financial harvesting aggregated finding
    - Deceptive CTA button ('Update KYC Now')
    - Suspicious external script (pastebin.com)
    - Excessive hidden form fields
    """
    html = load_fixture("phishing_banking_kyc.html")
    result = analyze_html(html, "https://sbi-kyc-portal.online/netbanking")

    assert result.has_login_form is True
    assert "State Bank of India (SBI)" in result.brand_mismatches
    assert "Bank Account / IFSC" in result.sensitive_fields
    assert "Aadhaar Number" in result.sensitive_fields
    assert "PAN Number" in result.sensitive_fields
    assert "Payment Card (PAN/CVV)" in result.sensitive_fields
    assert "OTP / 2FA" in result.sensitive_fields
    assert result.total_risk_points == 100
    assert result.max_severity == "critical"

    # Verify Bank Account & IFSC finding
    bank_f = next(f for f in result.findings if f.evidence.get("detector_type") == "bank_account")
    assert bank_f.category == "phishing"
    assert bank_f.severity == "high"
    assert "account_number" in bank_f.evidence.get("input_fields", [])

    # Verify Aadhaar & PAN finding
    govid_f = next(f for f in result.findings if f.evidence.get("detector_type") == "government_id")
    assert govid_f.category == "phishing"
    assert govid_f.severity == "high"
    assert govid_f.evidence.get("has_aadhaar") is True
    assert govid_f.evidence.get("has_pan") is True

    # Verify Multi-vector harvesting compound finding
    multi_f = next(f for f in result.findings if f.evidence.get("detector_type") == "multi_vector_harvesting")
    assert multi_f.category == "phishing"
    assert multi_f.severity == "critical"
    assert multi_f.risk_points == 35

    # Verify Deceptive CTA ('Update KYC Now')
    cta_f = next(f for f in result.findings if f.evidence.get("detector_type") == "deceptive_cta")
    assert "Update KYC" in cta_f.evidence.get("button_text", "")

    # Verify Suspicious external script (pastebin)
    script_f = next(f for f in result.findings if f.evidence.get("detector_type") == "suspicious_script")
    assert "pastebin.com" in script_f.evidence.get("script_src", "")


def test_phishing_upi_scam_page():
    """
    Fake reward lottery claim page soliciting UPI ID & UPI PIN:
    Must detect:
    - UPI ID & confidential UPI PIN fields
    - Fraudulent reward/lottery lure
    - Deceptive CTA button ('Claim Reward')
    - Hidden iframe
    """
    html = load_fixture("phishing_upi_scam.html")
    result = analyze_html(html, "https://festive-cashback-reward.site/claim")

    assert "UPI ID / PIN" in result.sensitive_fields
    assert result.total_risk_points >= 50
    assert result.max_severity == "critical"

    upi_f = next(f for f in result.findings if f.evidence.get("detector_type") == "upi_field")
    assert upi_f.category == "phishing"
    assert upi_f.severity == "critical"
    assert "upi_pin" in upi_f.evidence.get("input_fields", [])

    cta_f = next(f for f in result.findings if f.evidence.get("detector_type") == "deceptive_cta")
    assert "Claim Reward" in cta_f.evidence.get("button_text", "")


def test_ambiguous_brand_discussion_page():
    """
    Tech discussion blog mentioning Google, Apple, and PayPal in prose:
    Should NOT trigger brand mismatch (brand not claimed as site identity),
    and have zero login or harvesting findings.
    """
    html = load_fixture("ambiguous_brand_discussion.html")
    result = analyze_html(html, "https://cybertech-review.org/article/passkeys")

    assert result.has_login_form is False
    assert result.has_credential_harvesting is False
    assert len(result.brand_mismatches) == 0
    assert len(result.sensitive_fields) == 0
    assert result.total_risk_points == 0
    assert result.max_severity == "info"


def test_database_persistence_of_findings():
    """
    Verify that findings are persisted into the scan_findings database table
    with accurate category, severity, confidence, evidence JSON, and risk points.
    """
    html = load_fixture("phishing_credential_harvesting.html")
    result = analyze_html(html, "https://paypa1-security.xyz/login")

    session = local_session_factory()
    try:
        # Create a mock scan record
        scan_id = uuid.uuid4()
        scan = Scan(
            id=scan_id,
            input_url="https://paypa1-security.xyz/login",
            normalized_url="https://paypa1-security.xyz/login",
            status="running",
        )
        session.add(scan)
        session.commit()

        # Persist findings
        db_records = save_findings_to_db_sync(
            scan_id=scan_id,
            findings=result.findings,
            db=session,
        )

        assert len(db_records) >= 4

        # Query back from DB
        stored = session.query(ScanFinding).filter(ScanFinding.scan_id == scan_id).all()
        assert len(stored) == len(db_records)

        for record in stored:
            assert record.category == "phishing"
            assert record.severity in ("critical", "high", "medium", "low", "info")
            assert 0.0 <= record.confidence <= 1.0
            assert isinstance(record.evidence, dict)
            assert "detector_type" in record.evidence
            assert record.risk_points >= 0
            assert record.recommendation is not None
    finally:
        session.close()


def test_ssrf_safety_in_content_analyzer():
    """
    Verify strict SSRF safety boundaries in content analyzer:
    Blocks private IPs, loopback, cloud metadata, and non-HTTP protocols.
    """
    # Prohibited loopback & private IPs
    assert is_safe_url("http://127.0.0.1/admin", resolve_dns=False) is False
    assert is_safe_url("http://localhost:8000/", resolve_dns=False) is False
    assert is_safe_url("http://10.0.0.1/secret", resolve_dns=False) is False
    assert is_safe_url("http://192.168.1.1/", resolve_dns=False) is False
    assert is_safe_url("http://172.16.0.1/", resolve_dns=False) is False
    assert is_safe_url("http://0.0.0.0/", resolve_dns=False) is False

    # Prohibited cloud metadata
    assert is_safe_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False) is False
    assert is_safe_url("http://metadata.google.internal/computeMetadata/v1/", resolve_dns=False) is False

    # Prohibited schemes
    assert is_safe_url("ftp://example.com/file", resolve_dns=False) is False
    assert is_safe_url("javascript:alert(1)", resolve_dns=False) is False
    assert is_safe_url("file:///etc/passwd", resolve_dns=False) is False

    # Allowed public URLs
    assert is_safe_url("https://github.com", resolve_dns=False) is True
    assert is_safe_url("https://sbi.co.in", resolve_dns=False) is True
    assert is_safe_url("https://onlinesbi.sbi", resolve_dns=False) is True
