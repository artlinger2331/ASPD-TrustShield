"""
Unit tests for CA Trust & Incident Monitor.
Tests distrusted CAs, incident registry, weak key generation, and ROCA detection.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from app.services.ca_trust_monitor import (
    check_ca_trust,
    check_weak_key_generation,
    is_roca_vulnerable,
    get_all_distrusted_and_incident_cas,
    DISTRUSTED_CAS,
    KNOWN_CA_INCIDENTS,
)


def test_trusted_ca_evaluation():
    """Verify standard legitimate CAs pass without trust penalties."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=DigiCert Global Root CA, O=DigiCert Inc, C=US",
        subject_str="CN=example.com",
    )
    assert status == "trusted"
    assert incident is None
    assert finding is None


def test_self_signed_ca_evaluation():
    """Verify self-signed certificates are flagged as self_signed with critical finding."""
    dn = "CN=untrusted-self-signed.local, O=Testing Corp"
    status, incident, finding = check_ca_trust(
        issuer_str=dn,
        subject_str=dn,
    )
    assert status == "self_signed"
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.risk_points >= 30
    assert "Self-Signed" in finding.title


def test_distrusted_ca_wosign():
    """Verify WoSign certificates are flagged as distrusted with critical severity."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=WoSign Class 3 Extended Validation Server CA, O=WoSign, C=CN",
        subject_str="CN=compromised-site.com",
    )
    assert status == "distrusted"
    assert incident is not None
    assert incident["ca_name"] == "WoSign CA"
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.risk_points >= 30


def test_distrusted_ca_startcom():
    """Verify StartCom/StartSSL is flagged as distrusted."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=StartCom Certification Authority, O=StartCom Ltd., C=IL",
        subject_str="CN=site.com",
    )
    assert status == "distrusted"
    assert incident["ca_name"] == "StartCom (StartSSL)"


def test_distrusted_ca_diginotar():
    """Verify DigiNotar rogue CA is flagged as distrusted."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=DigiNotar Root CA, O=DigiNotar, C=NL",
        subject_str="CN=site.com",
    )
    assert status == "distrusted"
    assert incident["ca_name"] == "DigiNotar"


def test_distrusted_ca_symantec_legacy():
    """Verify Symantec legacy roots are flagged as distrusted."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=Symantec Class 3 Secure Server CA, O=Symantec Corporation, C=US",
        subject_str="CN=site.com",
    )
    assert status == "distrusted"
    assert "Symantec" in incident["ca_name"]


def test_known_incident_trustcor():
    """Verify TrustCor Systems is flagged for known trust incidents."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=TrustCor RootCert CA-1, O=TrustCor Systems S.de R.L., C=PA",
        subject_str="CN=tracked-host.com",
    )
    assert status == "incident_flagged"
    assert incident is not None
    assert incident["incident_type"] == "surveillance_ties"
    assert finding is not None
    assert finding.severity == "critical"
    assert "TrustCor" in finding.title


def test_known_incident_etugra():
    """Verify e-Tugra is flagged for sub-CA misissuance incident."""
    status, incident, finding = check_ca_trust(
        issuer_str="CN=E-Tugra Certification Authority, O=E-Tugra, C=TR",
        subject_str="CN=site.com",
    )
    assert status == "incident_flagged"
    assert incident["incident_type"] == "misissuance"


def test_weak_key_generation_small_rsa():
    """Verify RSA keys smaller than 2048 bits generate high severity finding."""
    key_1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    is_weak, finding = check_weak_key_generation(key_1024.public_key())
    assert is_weak is True
    assert finding is not None
    assert finding.severity == "high"
    assert "1024-bit" in finding.title


def test_strong_key_generation_rsa_2048():
    """Verify 2048-bit RSA keys pass cleanly."""
    key_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    is_weak, finding = check_weak_key_generation(key_2048.public_key())
    assert is_weak is False
    assert finding is None


def test_weak_key_generation_dsa():
    """Verify DSA keys generate deprecation finding."""
    key_dsa = dsa.generate_private_key(key_size=1024)
    is_weak, finding = check_weak_key_generation(key_dsa.public_key())
    assert is_weak is True
    assert finding is not None
    assert "DSA" in finding.title


def test_weak_key_generation_small_ecc():
    """Verify ECC curves under 256 bits generate weak key finding."""
    key_ecc_192 = ec.generate_private_key(ec.SECP192R1())
    is_weak, finding = check_weak_key_generation(key_ecc_192.public_key())
    assert is_weak is True
    assert finding is not None
    assert "192-bit" in finding.title


def test_strong_key_generation_ecc_256():
    """Verify standard P-256 (secp256r1) curve passes cleanly."""
    key_ecc_256 = ec.generate_private_key(ec.SECP256R1())
    is_weak, finding = check_weak_key_generation(key_ecc_256.public_key())
    assert is_weak is False
    assert finding is None


def test_roca_vulnerability_detector():
    """Verify ROCA detector returns False for standard non-ROCA RSA keys."""
    key_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = key_2048.public_key().public_numbers().n
    # Standard cryptographically secure RSA modulus must NOT trigger ROCA
    assert is_roca_vulnerable(n) is False


def test_get_all_distrusted_and_incident_cas():
    """Verify full registry export contains expected roots."""
    records = get_all_distrusted_and_incident_cas()
    assert len(records) >= 8
    ca_names = [r["ca_name"] for r in records]
    assert any("WoSign" in name for name in ca_names)
    assert any("DigiNotar" in name for name in ca_names)
    assert any("TrustCor" in name for name in ca_names)
