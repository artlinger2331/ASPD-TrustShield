"""
<<<<<<< .merge_file_nQhGDe
Unit tests for TrustShield URL Feature Extractor.
Tests all 20 required features, dual output formats (human-readable report + numerical vector),
and verifies behavior on normal URLs, phishing-like URLs, IP URLs, shorteners, homoglyphs, and edge cases.
"""

import json
from pathlib import Path
import pytest

from app.ml.feature_extractor import (
    ExtractedFeatureReport,
    FeatureSchemaV1,
    calculate_shannon_entropy,
    extract_feature_report,
    extract_features,
    extract_features_vector,
    extract_max_char_repetition,
=======
Unit tests for the TrustShield URL Feature Extractor and Schema v1.0.0.
"""

import pytest

from app.ml.feature_extractor import (
    FeatureSchemaV1,
    calculate_shannon_entropy,
    extract_features,
    extract_features_vector,
>>>>>>> .merge_file_aybxGC
    is_ip_host,
    parse_subdomain_parts,
)


<<<<<<< .merge_file_nQhGDe
def test_feature_schema_v1_specification():
    """Verify that FeatureSchemaV1 contains exactly the 20 required features in order."""
    assert FeatureSchemaV1.feature_count() == 20
    names = FeatureSchemaV1.feature_names()
    assert len(names) == 20
    assert len(set(names)) == 20

    expected_features = [
        "url_length",
        "domain_length",
        "num_dots",
        "num_hyphens",
        "num_digits",
        "num_special_chars",
        "num_subdomains",
        "domain_age_days",
        "has_ip_address",
        "uses_https",
        "suspicious_keyword_count",
        "brand_keyword_count",
        "suspicious_tld",
        "is_url_shortener",
        "redirect_count",
        "domain_entropy",
        "char_repetition_max",
        "path_depth",
        "query_param_count",
        "has_embedded_credentials",
    ]
    assert names == expected_features


def test_schema_json_export(tmp_path: Path):
    """Verify that the schema can be exported as a valid JSON file."""
    schema_file = tmp_path / "url_feature_schema.json"
    json_str = FeatureSchemaV1.export_schema_json(schema_file)

    assert schema_file.exists()
    parsed = json.loads(json_str)
    assert parsed["version"] == "v1.0.0"
    assert parsed["feature_count"] == 20
    assert len(parsed["features"]) == 20


# 1. Normal Benign URLs
def test_normal_benign_urls():
    """Verify extraction on standard, benign authoritative websites."""
    url = "https://www.google.com/search?q=cybersecurity"
    features = extract_features(url)
    vector = extract_features_vector(url)
    report = extract_feature_report(url)

    assert features["url_length"] == len(url)
    assert features["domain_length"] == len("www.google.com")
    assert features["uses_https"] == 1
    assert features["has_ip_address"] == 0
    assert features["has_embedded_credentials"] == 0
    assert features["is_url_shortener"] == 0
    assert features["suspicious_tld"] == 0
    assert features["num_subdomains"] == 1  # www
    assert features["path_depth"] == 1  # /search
    assert features["query_param_count"] == 1  # q=cybersecurity

    # Vector output check
    assert len(vector) == 20
    assert vector[0] == float(len(url))

    # Report structure check
    assert isinstance(report, ExtractedFeatureReport)
    assert report.feature_count == 20
    assert report.summary_flags["uses_https"] is True
    assert report.summary_flags["is_ip_address"] is False
    assert report.summary_flags["has_credentials"] is False


# 2. Phishing-like URLs
def test_phishing_like_urls():
    """Verify detection of multi-signal phishing URLs."""
    url = "http://paypal-verification.account-update.xyz/login.php?client_id=123"
    features = extract_features(url)
    report = extract_feature_report(url)

    assert features["uses_https"] == 0
    assert features["suspicious_tld"] == 1  # .xyz
    assert features["brand_keyword_count"] >= 1  # paypal
    assert features["suspicious_keyword_count"] >= 2  # verification, login
    assert features["num_subdomains"] >= 1  # paypal-verification
    assert features["num_hyphens"] >= 2
    assert features["num_digits"] == 3  # 123

    # Human-readable flags
    assert report.summary_flags["has_suspicious_tld"] is True
    assert report.summary_flags["has_suspicious_keywords"] is True
    assert report.summary_flags["has_brand_in_domain"] is True
    assert report.features["suspicious_tld"].is_suspicious is True
    assert report.features["uses_https"].is_suspicious is True


# 3. IP-based URLs
def test_ip_based_urls():
    """Verify handling of direct IPv4 and IPv6 URLs."""
    # IPv4 with custom port
    ipv4_url = "http://192.168.1.1:8080/admin/login"
    features_ipv4 = extract_features(ipv4_url)
    report_ipv4 = extract_feature_report(ipv4_url)

    assert features_ipv4["has_ip_address"] == 1
    assert features_ipv4["domain_length"] == len("192.168.1.1")
    assert features_ipv4["num_dots"] == 3
    assert features_ipv4["path_depth"] == 2
    assert report_ipv4.summary_flags["is_ip_address"] is True
    assert report_ipv4.features["has_ip_address"].is_suspicious is True

    # Public IPv4
    pub_ip_url = "http://45.33.32.156/bank/update.php"
    features_pub = extract_features(pub_ip_url)
    assert features_pub["has_ip_address"] == 1

    # IPv6 bracketed
    ipv6_url = "http://[2001:db8::1]/index.html"
    features_ipv6 = extract_features(ipv6_url)
    assert features_ipv6["has_ip_address"] == 1


# 4. URL Shorteners
def test_url_shorteners():
    """Verify shortener identification across multiple popular services."""
    short_urls = [
        "http://bit.ly/secure-login",
        "https://tinyurl.com/bank-auth",
        "http://t.co/abc1234",
        "https://cutt.ly/phish-target",
        "https://rb.gy/fake-update",
    ]

    for short_url in short_urls:
        features = extract_features(short_url)
        report = extract_feature_report(short_url)
        assert features["is_url_shortener"] == 1, f"Failed for {short_url}"
        assert report.summary_flags["is_url_shortener"] is True


# 5. Homoglyphs & Punycode URLs
def test_homoglyphs_punycode_urls():
    """Verify handling of internationalized punycode domains."""
    url = "https://xn--pple-43d.com/auth/login.html"
    features = extract_features(url)

    assert features["domain_length"] == len("xn--pple-43d.com")
    assert features["num_hyphens"] >= 2  # xn--
    assert features["suspicious_keyword_count"] >= 2  # auth, login
    assert features["uses_https"] == 1
    assert features["domain_entropy"] > 2.0


# 6. Edge Cases
def test_edge_case_empty_and_whitespace_url():
    """Verify graceful zero-safe behavior on empty or blank inputs."""
    for empty_val in ("", "   ", None):
        features = extract_features(empty_val)
        vector = extract_features_vector(empty_val)
        report = extract_feature_report(empty_val)

        assert features["url_length"] == 0
        assert features["domain_length"] == 0
        assert features["domain_age_days"] == -1
        assert len(vector) == 20
        assert isinstance(report.to_dict(), dict)


def test_edge_case_missing_scheme():
    """Verify auto-prefixing when scheme is omitted."""
    url = "example.com/dashboard?view=full"
    features = extract_features(url)

    assert features["domain_length"] == len("example.com")
    assert features["uses_https"] == 0
    assert features["path_depth"] == 1
    assert features["query_param_count"] == 1


def test_edge_case_embedded_credentials():
    """Verify detection of embedded credentials in authority component."""
    # Standard user:password@host
    url1 = "http://admin:secretPass123@fakebank.com/transfer"
    features1 = extract_features(url1)
    report1 = extract_feature_report(url1)

    assert features1["has_embedded_credentials"] == 1
    assert report1.summary_flags["has_credentials"] is True
    assert report1.features["has_embedded_credentials"].is_suspicious is True

    # User-only @host
    url2 = "http://user@paypal-verify.xyz/auth"
    features2 = extract_features(url2)
    assert features2["has_embedded_credentials"] == 1


def test_edge_case_char_repetition():
    """Verify character repetition run extraction."""
    repeat_url = "http://aaaaaaaaaaaaaaaa.com/00000000"
    features = extract_features(repeat_url)
    report = extract_feature_report(repeat_url)

    assert features["char_repetition_max"] == 16  # 'a' repeated 16 times
    assert report.summary_flags["has_high_repetition"] is True
    assert report.features["char_repetition_max"].is_suspicious is True

    normal_url = "https://example.com/test"
    assert extract_max_char_repetition(normal_url) == 2  # '//' or 'tt'


def test_edge_case_special_characters():
    """Verify special character counting outside standard delimiters."""
    url = "https://test.com/path?token=xyz_123&user=admin%20root!#frag~"
    features = extract_features(url)

    # Contains: ?, =, _, &, =, %, !, #, ~
    assert features["num_special_chars"] >= 8


def test_scan_metadata_integration_and_fallbacks():
    """Verify scan metadata ingestion and offline fallback sentinel defaults."""
    url = "https://example.org"

    # With metadata
    metadata = {
        "domain_age_days": 1825,
        "redirect_count": 4,
        "is_shortener": 1,
    }
    features_meta = extract_features(url, metadata=metadata)
    assert features_meta["domain_age_days"] == 1825
    assert features_meta["redirect_count"] == 4
    assert features_meta["is_url_shortener"] == 1

    # Without metadata (offline fallbacks)
    features_fallback = extract_features(url, metadata=None)
    assert features_fallback["domain_age_days"] == -1
    assert features_fallback["redirect_count"] == 0
    assert features_fallback["is_url_shortener"] == 0
=======
def test_feature_schema_completeness():
    """Verify that FeatureSchemaV1 defines exactly 42 features."""
    assert FeatureSchemaV1.feature_count() == 42
    assert len(FeatureSchemaV1.feature_names()) == 42
    assert len(set(FeatureSchemaV1.feature_names())) == 42  # No duplicates


def test_shannon_entropy():
    """Verify Shannon entropy calculation."""
    assert calculate_shannon_entropy("") == 0.0
    # Homogeneous string has 0 entropy
    assert calculate_shannon_entropy("aaaaaa") == 0.0
    # Random / diverse string has positive entropy
    ent = calculate_shannon_entropy("abcdef123456!@#$")
    assert ent > 3.0


def test_is_ip_host():
    """Verify IPv4 and IPv6 detection."""
    assert is_ip_host("192.168.1.1") is True
    assert is_ip_host("10.0.0.1") is True
    assert is_ip_host("127.0.0.1:8080") is True
    assert is_ip_host("google.com") is False
    assert is_ip_host("paypal-verify.xyz") is False
    assert is_ip_host("") is False


def test_parse_subdomain_parts():
    """Verify subdomain and domain decomposition."""
    sub, sld, tld = parse_subdomain_parts("www.google.com")
    assert sub == ["www"]
    assert sld == "google"
    assert tld == ".com"

    sub2, sld2, tld2 = parse_subdomain_parts("paypal.com.verify.account.xyz")
    assert sub2 == ["paypal", "com", "verify"]
    assert sld2 == "account"
    assert tld2 == ".xyz"

    sub3, sld3, tld3 = parse_subdomain_parts("example.co.uk")
    assert sub3 == []
    assert sld3 == "example"
    assert tld3 == ".co.uk"


def test_extract_features_keys_match_schema():
    """Verify that extract_features produces a dictionary with all 42 schema features."""
    url = "https://www.example.com/login?token=abc"
    features = extract_features(url)

    assert len(features) == 42
    for name in FeatureSchemaV1.feature_names():
        assert name in features, f"Missing feature: {name}"

    assert FeatureSchemaV1.validate_features_dict(features) is True


def test_extract_features_vector():
    """Verify extract_features_vector outputs a list of 42 numeric values in strict schema order."""
    url = "https://www.example.com/test"
    vector = extract_features_vector(url)

    assert isinstance(vector, list)
    assert len(vector) == 42
    assert all(isinstance(v, (int, float)) for v in vector)


def test_extract_features_phishing_signals():
    """Verify detection of suspicious phishing indicators."""
    phishing_url = "http://paypal.account-verify.xyz:8080/paypal.com/login.php?client_id=123"
    features = extract_features(phishing_url)

    assert features["is_https"] == 0
    assert features["has_custom_port"] == 1
    assert features["suspicious_tld"] == 1
    assert features["brand_in_subdomain"] == 1
    assert features["tld_in_path"] == 1
    assert features["sensitive_word_count"] >= 2  # verify, login
    assert features["num_subdomains"] >= 1


def test_extract_features_ip_host():
    """Verify handling of direct IP host."""
    ip_url = "http://192.168.1.100/admin"
    features = extract_features(ip_url)

    assert features["is_ip_address"] == 1
    assert features["hostname_length"] == len("192.168.1.100")


def test_extract_features_punycode():
    """Verify punycode homoglyph detection."""
    puny_url = "https://xn--pple-43d.com/auth"
    features = extract_features(puny_url)

    assert features["has_punycode"] == 1
    assert features["sensitive_word_count"] >= 1  # auth


def test_extract_features_offline_fallbacks():
    """Verify that domain and redirect features return safe defaults when context is omitted."""
    url = "https://safe-site.org/index.html"
    features = extract_features(url)

    assert features["domain_age_days"] == -1
    assert features["days_to_expiry"] == -1
    assert features["is_private_whois"] == 0
    assert features["num_dns_records"] == 0
    assert features["ttl_value"] == -1
    assert features["redirect_count"] == 0
    assert features["has_cross_domain_redirect"] == 0
    assert features["http_status_code"] == 200
    assert features["response_time_ms"] == -1.0


def test_extract_features_with_context():
    """Verify that contextual information is properly incorporated."""
    url = "https://analyzed-domain.com"
    context = {
        "domain_age_days": 1250,
        "days_to_expiry": 300,
        "is_private_whois": 1,
        "num_dns_records": 4,
        "has_mx_records": 1,
        "has_txt_records": 1,
        "ttl_value": 3600,
        "redirect_count": 2,
        "has_cross_domain_redirect": 1,
        "http_status_code": 301,
        "response_time_ms": 142.5,
    }
    features = extract_features(url, context=context)

    assert features["domain_age_days"] == 1250
    assert features["days_to_expiry"] == 300
    assert features["is_private_whois"] == 1
    assert features["num_dns_records"] == 4
    assert features["has_mx_records"] == 1
    assert features["has_txt_records"] == 1
    assert features["ttl_value"] == 3600
    assert features["redirect_count"] == 2
    assert features["has_cross_domain_redirect"] == 1
    assert features["http_status_code"] == 301
    assert features["response_time_ms"] == 142.5
>>>>>>> .merge_file_aybxGC
