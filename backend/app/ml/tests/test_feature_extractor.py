"""
Unit tests for the TrustShield URL Feature Extractor and Schema v1.0.0.
"""

import pytest

from app.ml.feature_extractor import (
    FeatureSchemaV1,
    calculate_shannon_entropy,
    extract_features,
    extract_features_vector,
    is_ip_host,
    parse_subdomain_parts,
)


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
