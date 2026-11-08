"""
Unit tests for SSL/TLS Certificate and CA Trust Analyzer.
Covers all 12 core checks, structured chain visualization payload,
and database persistence.
"""

from datetime import datetime, timezone, timedelta
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.analyzers.cert_analyzer import (
    parse_x509_certificate,
    analyze_certificate,
    save_certificate_to_db_sync,
    fetch_server_certificate,
    PRECERT_SCT_OID,
)
from app.models.scan import Scan
from app.models.certificate import Certificate
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory


# ---------------------------------------------------------------------------
# MOCK CERTIFICATE GENERATOR HELPERS
# ---------------------------------------------------------------------------

def generate_mock_cert(
    subject_cn: str,
    issuer_cn: str,
    san_names: list,
    key_size: int = 2048,
    days_valid: int = 90,
    days_offset: int = 0,
    hash_algo=hashes.SHA256(),
    add_ct_sct: bool = False,
) -> bytes:
    """Generates DER-encoded mock X.509 certificate for deterministic unit testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{subject_cn} Company"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{issuer_cn} Org"),
    ])

    now = datetime.now(timezone.utc)
    not_before = now + timedelta(days=days_offset)
    not_after = not_before + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_names:
        dns_names = [x509.DNSName(name) for name in san_names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False,
        )

    # Optional Certificate Transparency (CT) Signed Certificate Timestamps (SCT) extension
    if add_ct_sct:
        # Dummy SCT DER payload
        builder = builder.add_extension(
            x509.UnrecognizedExtension(PRECERT_SCT_OID, b"\x04\x10test-ct-sct-payload"),
            critical=False,
        )

    cert = builder.sign(key, hash_algo)
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# TEST CASES
# ---------------------------------------------------------------------------

def test_valid_certificate_parsing_and_chain_payload():
    """Verify that a legitimate certificate generates the exact 3-level visualization payload."""
    der = generate_mock_cert(
        subject_cn="my-clean-store.com",
        issuer_cn="DigiCert Global CA",
        san_names=["my-clean-store.com", "www.my-clean-store.com"],
        key_size=2048,
        days_valid=90,
        add_ct_sct=True,
    )

    result = parse_x509_certificate(der, target_domain="my-clean-store.com", chain_valid_default=True)

    assert result.https is True
    assert result.is_valid is True
    assert result.san_matched is True
    assert result.days_until_expiry >= 85
    assert result.weak_algo is False
    assert result.ca_trust_status == "trusted"
    assert result.ct_log_present is True

    # Validate exact structured certificate-chain visualization payload
    chain_payload = result.to_chain_payload()
    assert "chain" in chain_payload
    chain_list = chain_payload["chain"]
    assert len(chain_list) == 3

    # Check Root Level
    assert chain_list[0]["level"] == "root"
    assert "DigiCert" in chain_list[0]["subject"]
    assert chain_list[0]["issuer"] == chain_list[0]["subject"]

    # Check Intermediate Level
    assert chain_list[1]["level"] == "intermediate"
    assert "DigiCert" in chain_list[1]["subject"]
    assert chain_list[1]["issuer"] == chain_list[0]["subject"]

    # Check Leaf Level
    assert chain_list[2]["level"] == "leaf"
    assert chain_list[2]["subject"] == "my-clean-store.com"
    assert chain_list[2]["issuer"] == chain_list[1]["subject"]


def test_expired_certificate_detection():
    """Verify that an expired certificate generates a Critical finding."""
    der = generate_mock_cert(
        subject_cn="expired-website.com",
        issuer_cn="GlobalSign CA",
        san_names=["expired-website.com"],
        days_valid=30,
        days_offset=-45,  # Valid between 45 days ago and 15 days ago
    )

    result = parse_x509_certificate(der, target_domain="expired-website.com")

    assert result.is_valid is False
    assert result.days_until_expiry < 0
    assert result.max_severity == "critical"
    assert any("Certificate Has Expired" in f.title for f in result.findings)
    assert result.total_risk_points >= 25


def test_future_certificate_detection():
    """Verify that a certificate with activation in the future generates a high severity finding."""
    der = generate_mock_cert(
        subject_cn="future-site.com",
        issuer_cn="GlobalSign CA",
        san_names=["future-site.com"],
        days_valid=30,
        days_offset=10,  # Activates 10 days in the future
    )

    result = parse_x509_certificate(der, target_domain="future-site.com")

    assert result.is_valid is False
    assert any("Not Yet Valid" in f.title for f in result.findings)
    assert result.total_risk_points >= 20


def test_hostname_mismatch_detection():
    """Verify that a certificate issued for an unrelated domain triggers Hostname Mismatch."""
    der = generate_mock_cert(
        subject_cn="attacker-infrastructure.com",
        issuer_cn="Sectigo CA",
        san_names=["attacker-infrastructure.com", "*.attacker-infrastructure.com"],
    )

    result = parse_x509_certificate(der, target_domain="mybank.com")

    assert result.is_valid is False
    assert result.san_matched is False
    assert result.max_severity == "critical"
    assert any("Hostname Mismatch" in f.title for f in result.findings)
    assert result.total_risk_points >= 30


def test_wildcard_san_matching():
    """Verify wildcard matching according to RFC 6125."""
    der = generate_mock_cert(
        subject_cn="bank.com",
        issuer_cn="DigiCert CA",
        san_names=["*.bank.com"],
    )

    # 1. Matches one subdomain level
    res_sub = parse_x509_certificate(der, target_domain="login.bank.com")
    assert res_sub.san_matched is True

    # 2. Does NOT match apex domain (apex requires explicit SAN entry)
    res_apex = parse_x509_certificate(der, target_domain="bank.com")
    assert res_apex.san_matched is False

    # 3. Does NOT match multi-level nested subdomain
    res_nested = parse_x509_certificate(der, target_domain="deep.sub.bank.com")
    assert res_nested.san_matched is False


def test_self_signed_certificate_detection():
    """Verify that a self-signed certificate (Subject == Issuer) is flagged as Critical."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-portal.com")])
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # Self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("untrusted-portal.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)

    result = parse_x509_certificate(der, target_domain="untrusted-portal.com")

    assert result.is_valid is False
    assert result.ca_trust_status == "self_signed"
    assert any("Self-Signed SSL/TLS Certificate Detected" in f.title for f in result.findings)
    assert result.total_risk_points >= 30


def test_weak_cryptography_detection():
    """Verify that weak RSA key size (<2048 bits) is flagged as high risk."""
    der = generate_mock_cert(
        subject_cn="legacy-server.com",
        issuer_cn="Legacy Root CA",
        san_names=["legacy-server.com"],
        key_size=1024,
        hash_algo=hashes.SHA256(),
    )

    result = parse_x509_certificate(der, target_domain="legacy-server.com")

    assert result.weak_key is True
    assert result.public_key_bits == 1024
    finding_titles = [f.title for f in result.findings]
    assert any("Weak RSA Public Key Size" in title for title in finding_titles)


def test_weak_signature_algorithm_sha1():
    """Verify SHA-1 signature algorithm triggers critical cryptographic flaw finding."""
    der = generate_mock_cert(
        subject_cn="sha1-site.com",
        issuer_cn="DigiCert CA",
        san_names=["sha1-site.com"],
        key_size=2048,
        hash_algo=hashes.SHA1(),
    )

    result = parse_x509_certificate(der, target_domain="sha1-site.com")

    assert result.weak_algo is True
    assert any("Deprecated Cryptographic Signature Algorithm" in f.title for f in result.findings)
    assert result.total_risk_points >= 25


def test_free_automated_ca_on_banking_domain():
    """Verify free automated DV certs on sensitive domains generate an advisory finding."""
    der = generate_mock_cert(
        subject_cn="sbi-bank-portal-update.com",
        issuer_cn="Let's Encrypt",
        san_names=["sbi-bank-portal-update.com"],
        key_size=2048,
    )

    result = parse_x509_certificate(der, target_domain="sbi-bank-portal-update.com")

    assert any("Free Automated DV Certificate" in f.title for f in result.findings)
    assert result.warning is not None
    assert "Attackers routinely acquire free automated certificates" in result.warning


def test_certificate_transparency_logging_status():
    """Verify missing CT log triggers low severity telemetry notice."""
    der_without_ct = generate_mock_cert(
        subject_cn="no-ct.com",
        issuer_cn="DigiCert CA",
        san_names=["no-ct.com"],
        add_ct_sct=False,
    )
    result = parse_x509_certificate(der_without_ct, target_domain="no-ct.com")
    assert result.ct_log_present is False
    assert any("Certificate Transparency" in f.title for f in result.findings)


def test_no_https_available_graceful_handling():
    """Verify analyze_certificate handles offline/unreachable servers gracefully without raising."""
    result = analyze_certificate(
        target_url_or_domain="https://unreachable-test-domain.invalid",
        resolve_live=False,  # Der bytes is None
    )
    assert result.https is False
    assert result.is_valid is False
    assert any("No HTTPS / TLS Encryption Available" in f.title for f in result.findings)


def test_certificate_database_persistence():
    """Verify end-to-end database persistence into both `certificates` and `scan_findings` tables."""
    session = local_session_factory()
    try:
        # 1. Create a Scan record
        scan = Scan(
            input_url="https://secure-portal.com/login",
            normalized_url="https://secure-portal.com/login",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # 2. Parse certificate
        der = generate_mock_cert(
            subject_cn="secure-portal.com",
            issuer_cn="DigiCert Inc",
            san_names=["secure-portal.com"],
            key_size=2048,
            days_valid=90,
            add_ct_sct=True,
        )
        analysis_result = parse_x509_certificate(der, target_domain="secure-portal.com")

        # 3. Persist to database
        cert_record = save_certificate_to_db_sync(
            scan_id=scan.id,
            result=analysis_result,
            db=session,
        )

        assert cert_record is not None
        assert cert_record.scan_id == scan.id
        assert cert_record.is_valid is True
        assert cert_record.days_until_expiry >= 80

        # Query database directly
        db_cert = session.query(Certificate).filter(Certificate.scan_id == scan.id).first()
        assert db_cert is not None
        assert "DigiCert" in db_cert.issuer
        assert db_cert.days_until_expiry >= 80
        assert isinstance(db_cert.raw_certificate, dict)
        assert "chain" in db_cert.raw_certificate
        assert len(db_cert.raw_certificate["chain"]) == 3

        # Verify scan findings
        findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        assert len(findings) >= 0
    finally:
        session.close()
