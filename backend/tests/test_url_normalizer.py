"""
Unit tests for URL normalization and SSRF defense pipeline.
"""

import pytest
from app.analyzers.url_normalizer import (
    normalize_and_validate_url,
    defang_url,
    extract_domain_parts,
    detect_homoglyphs,
    check_ssrf_safety,
)


def test_defang_url():
    """Verify various defanged cyber indicator formats are restored to standard syntax."""
    assert defang_url("hxxps://evil[.]com/login") == "https://evil.com/login"
    assert defang_url("hxxp://phish(.)site[.]top/verify") == "http://phish.site.top/verify"
    assert defang_url("h**ps://bank[:]443/auth") == "https://bank:443/auth"
    assert defang_url("evil[dot]com") == "evil.com"
    assert defang_url("   <hxxps://attack{.}com>  ") == "https://attack.com"
    assert defang_url("https://clean-website.com") == "https://clean-website.com"


def test_extract_domain_parts():
    """Verify accurate extraction of base domain, subdomain, and TLDs including multi-part ccTLDs."""
    # Standard gTLD
    base, sub, tld = extract_domain_parts("login.secure.google.com")
    assert base == "google.com"
    assert sub == "login.secure"
    assert tld == "com"

    # Multi-part ccTLD (.co.uk)
    base, sub, tld = extract_domain_parts("portal.service.co.uk")
    assert base == "service.co.uk"
    assert sub == "portal"
    assert tld == "co.uk"

    # Multi-part ccTLD (.co.in)
    base, sub, tld = extract_domain_parts("secure-sbi.co.in")
    assert base == "secure-sbi.co.in"
    assert sub is None
    assert tld == "co.in"

    # Literal IP address
    base, sub, tld = extract_domain_parts("93.184.216.34")
    assert base == "93.184.216.34"
    assert sub is None
    assert tld == "ip"


def test_punycode_and_homoglyph_detection():
    """Verify IDN punycode and lookalike Cyrillic homoglyph detection."""
    # Cyrillic 'р' (U+0440) instead of Latin 'p'
    cyrillic_paypal = "\u0440aypal.com"
    has_homo, decoded = detect_homoglyphs(cyrillic_paypal)
    assert has_homo is True
    assert decoded == cyrillic_paypal

    # Standard Latin domain has no homoglyphs
    has_homo, decoded = detect_homoglyphs("paypal.com")
    assert has_homo is False
    assert decoded == "paypal.com"

    # Punycode string
    punycode_domain = "xn--pple-43d.com"  # apple with accented á
    has_homo, decoded = detect_homoglyphs(punycode_domain)
    assert decoded != punycode_domain


def test_url_normalization_canonicalization():
    """Verify scheme defaulting, port stripping, case canonicalization, and path traversal normalization."""
    # 1. Missing scheme defaults to https
    norm, err = normalize_and_validate_url("example.com/test", resolve_dns=False)
    assert err is None
    assert norm.scheme == "https"
    assert norm.host == "example.com"
    assert norm.path == "/test"
    assert norm.normalized_url == "https://example.com/test"

    # 2. Uppercase canonicalization and default port stripping
    norm, err = normalize_and_validate_url("HTTP://EXAMPLE.COM:80/Path/To/Resource", resolve_dns=False)
    assert err is None
    assert norm.scheme == "http"
    assert norm.host == "example.com"
    assert norm.port is None
    assert norm.normalized_url == "http://example.com/Path/To/Resource"

    # 3. Non-standard port preserved
    norm, err = normalize_and_validate_url("https://service.domain.org:8443/api/v1", resolve_dns=False)
    assert err is None
    assert norm.port == 8443
    assert norm.normalized_url == "https://service.domain.org:8443/api/v1"

    # 4. Path traversal resolution
    norm, err = normalize_and_validate_url("https://example.com/a/b/../c/./d", resolve_dns=False)
    assert err is None
    assert norm.path == "/a/c/d"

    # 5. Fragment stripped from normalized target
    norm, err = normalize_and_validate_url("https://example.com/page?query=1#comment-42", resolve_dns=False)
    assert err is None
    assert norm.query == "query=1"
    assert norm.fragment == "comment-42"
    assert "#" not in norm.normalized_url
    assert norm.normalized_url == "https://example.com/page?query=1"


def test_ssrf_prohibited_ip_ranges():
    """Verify that private, loopback, broadcast, and cloud metadata IPs are strictly blocked."""
    prohibited_ips = [
        "127.0.0.1",
        "127.0.0.100",
        "10.0.0.5",
        "10.254.1.2",
        "192.168.0.1",
        "192.168.100.254",
        "172.16.0.1",
        "172.31.255.255",
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "0.0.0.0",
        "100.64.0.1",       # CGNAT
        "192.0.2.1",        # TEST-NET-1
        "224.0.0.1",        # Multicast
        "255.255.255.255",  # Broadcast
        "[::1]",            # IPv6 loopback
        "[fe80::1]",        # IPv6 link-local
    ]

    for ip in prohibited_ips:
        norm, err = normalize_and_validate_url(f"http://{ip}/status", resolve_dns=False)
        assert norm is None, f"Expected {ip} to be blocked"
        assert "SSRF Protection" in err


def test_ssrf_prohibited_hostnames():
    """Verify that local and cloud metadata hostnames are blocked."""
    prohibited_hosts = [
        "localhost",
        "test.localhost",
        "server.local",
        "api.internal",
        "metadata.google.internal",
        "broadcasthost",
    ]

    for host in prohibited_hosts:
        norm, err = normalize_and_validate_url(f"https://{host}/admin", resolve_dns=False)
        assert norm is None, f"Expected {host} to be blocked"
        assert "Prohibited local/internal hostname" in err


def test_unsupported_protocols_blocked():
    """Verify non-web protocol schemes are safely rejected."""
    blocked_urls = [
        "file:///etc/passwd",
        "ftp://ftp.example.com/files",
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "gopher://evil.com:70/1",
        "dict://dict.org",
        "ldap://ad.internal.corp",
    ]

    for target in blocked_urls:
        norm, err = normalize_and_validate_url(target, resolve_dns=False)
        assert norm is None
        assert "Unsupported URL scheme" in err


def test_valid_public_urls():
    """Verify legitimate public internet web URLs normalize cleanly."""
    valid_urls = [
        ("https://www.google.com", "https://www.google.com/"),
        ("https://github.com/torvalds/linux?tab=readme", "https://github.com/torvalds/linux?tab=readme"),
        ("http://sub.domain.co.uk:8080/path/view", "http://sub.domain.co.uk:8080/path/view"),
        ("https://cloudflare.com/ips-v4", "https://cloudflare.com/ips-v4"),
    ]

    for raw, expected in valid_urls:
        norm, err = normalize_and_validate_url(raw, resolve_dns=False)
        assert err is None
        assert norm is not None
        assert norm.normalized_url == expected


def test_detect_ip_based_urls():
    """Verify detection of public direct IP addresses in URL authority."""
    norm, err = normalize_and_validate_url("http://93.184.216.34/test", resolve_dns=False)
    assert err is None
    assert norm.is_ip is True
    assert norm.heuristics.is_ip is True
    assert any(f["title"] == "IP-Based Target Authority" for f in norm.heuristics.findings_list)


def test_detect_url_shorteners():
    """Verify known shorteners are flagged with medium severity findings."""
    norm, err = normalize_and_validate_url("https://bit.ly/3xY7kL9", resolve_dns=False)
    assert err is None
    assert norm.heuristics.is_shortener is True
    assert any(f["title"] == "Known URL Shortener Detected" for f in norm.heuristics.findings_list)

    norm2, _ = normalize_and_validate_url("https://tinyurl.com/secure-login", resolve_dns=False)
    assert norm2.heuristics.is_shortener is True


def test_detect_suspicious_keywords():
    """Verify detection of phishing lure keywords across path, query, and subdomains."""
    norm, err = normalize_and_validate_url(
        "https://portal.bank.com/account/security/verify?claim=reward&login=prompt",
        resolve_dns=False,
    )
    assert err is None
    found_keywords = set(norm.heuristics.suspicious_keywords_found)
    assert "account" in found_keywords
    assert "security" in found_keywords
    assert "verify" in found_keywords
    assert "claim" in found_keywords
    assert "reward" in found_keywords
    assert "login" in found_keywords
    assert any(f["title"] == "Deceptive Phishing Keywords in URL" for f in norm.heuristics.findings_list)


def test_detect_excessive_subdomains():
    """Verify domains with >= 3 subdomain labels trigger excessive subdomain warnings."""
    # 3 subdomains: login.verify.portal.evil.com
    norm, err = normalize_and_validate_url("https://login.verify.portal.evil.com/path", resolve_dns=False)
    assert err is None
    assert norm.heuristics.has_excessive_subdomains is True
    assert norm.heuristics.subdomain_count == 3
    assert any(f["title"] == "Excessive Subdomain Stacking" for f in norm.heuristics.findings_list)

    # 1 subdomain: standard
    norm_normal, _ = normalize_and_validate_url("https://docs.github.com/en", resolve_dns=False)
    assert norm_normal.heuristics.has_excessive_subdomains is False
    assert norm_normal.heuristics.subdomain_count == 1


def test_detect_suspicious_tlds():
    """Verify high-abuse/suspicious TLDs are flagged."""
    for tld in ["tk", "xyz", "top", "click", "loan", "work"]:
        norm, err = normalize_and_validate_url(f"https://account-update.{tld}/login", resolve_dns=False)
        assert err is None
        assert norm.heuristics.has_suspicious_tld is True
        assert any(f["title"] == "Suspicious / High-Abuse Top-Level Domain" for f in norm.heuristics.findings_list)


def test_detect_embedded_credentials():
    """Verify embedded userinfo credentials are detected, stripped from normalized URL, and flagged."""
    norm, err = normalize_and_validate_url("https://admin:SuperSecret123@target-portal.com/dashboard", resolve_dns=False)
    assert err is None
    assert norm.heuristics.has_embedded_credentials is True
    assert "admin:SuperSecret123@" not in norm.normalized_url
    assert norm.normalized_url == "https://target-portal.com/dashboard"
    assert any(f["title"] == "Deceptive Embedded Credentials in URL" for f in norm.heuristics.findings_list)


def test_detect_overly_long_url():
    """Verify URLs > 255 chars are flagged as long, and > 2048 chars are hard-rejected."""
    long_path = "a" * 260
    norm, err = normalize_and_validate_url(f"https://example.com/{long_path}", resolve_dns=False)
    assert err is None
    assert norm.heuristics.is_overly_long is True
    assert any(f["title"] == "Abnormally Long URL Structure" for f in norm.heuristics.findings_list)

    # Exceeding 2048 chars: hard rejection
    too_long = "https://example.com/" + ("b" * 2050)
    norm_bad, err_bad = normalize_and_validate_url(too_long, resolve_dns=False)
    assert norm_bad is None
    assert "maximum permissible length of 2048 characters" in err_bad


def test_query_params_and_fragment_parsing():
    """Verify structured parsing of query parameter dictionary and fragment separation."""
    norm, err = normalize_and_validate_url(
        "https://store.com/checkout?product_id=101&coupon=SAVE20&tag=electronics&tag=sale#payment-summary",
        resolve_dns=False,
    )
    assert err is None
    assert norm.query_params["product_id"] == "101"
    assert norm.query_params["coupon"] == "SAVE20"
    assert norm.query_params["tag"] == ["electronics", "sale"]
    assert norm.fragment == "payment-summary"
    assert norm.subdomain == "store"
    assert norm.base_domain == "store.com"
    assert norm.tld == "com"
    assert norm.path == "/checkout"


