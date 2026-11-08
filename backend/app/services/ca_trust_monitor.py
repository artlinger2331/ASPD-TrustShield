"""
TrustShield Certificate Authority (CA) Trust & Incident Monitor
Evaluates Certificate Authority trustworthiness, global trust-store status,
historical misissuance incidents, distrusted roots, and cryptographic key-generation flaws.
"""

import math
from typing import Dict, Any, Optional, Tuple, List, Set
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from app.schemas.content_analysis import ContentFindingSchema


# ---------------------------------------------------------------------------
# DISTRUSTED, REVOKED & INCIDENT-PRONE CA REGISTRY
# ---------------------------------------------------------------------------

DISTRUSTED_CAS: Dict[str, Dict[str, Any]] = {
    "wosign": {
        "name": "WoSign CA",
        "status": "distrusted",
        "severity": "critical",
        "description": "Distrusted globally by Mozilla, Apple, Google, and Microsoft due to backdated certificates and undisclosed acquisition.",
        "advisory": "https://blog.mozilla.org/security/2016/10/24/distrusting-new-wosign-and-startcom-certificates/",
    },
    "startcom": {
        "name": "StartCom (StartSSL)",
        "status": "distrusted",
        "severity": "critical",
        "description": "Distrusted globally following undisclosed acquisition by WoSign and falsified issuance practices.",
        "advisory": "https://blog.mozilla.org/security/2016/10/24/distrusting-new-wosign-and-startcom-certificates/",
    },
    "diginotar": {
        "name": "DigiNotar",
        "status": "distrusted",
        "severity": "critical",
        "description": "Compromised Dutch CA that issued 500+ rogue wildcard certificates (including *.google.com) used in state-sponsored MITM.",
        "advisory": "https://www.enisa.europa.eu/publications/info-notes/diginotar-compromise-final-report",
    },
    "cnnic": {
        "name": "CNNIC (China Internet Network Information Center)",
        "status": "distrusted",
        "severity": "critical",
        "description": "Untrusted in major root programs after delegating sub-CA capabilities used to generate unauthorized MITM certificates.",
        "advisory": "https://security.googleblog.com/2015/03/maintaining-digital-certificate-security.html",
    },
    "camerfirma": {
        "name": "Chambers of Commerce (Camerfirma)",
        "status": "distrusted",
        "severity": "high",
        "description": "Distrusted by Google Chrome and Mozilla due to prolonged systemic compliance and security failures.",
        "advisory": "https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/m_bNl0-3V9U",
    },
    "symantec": {
        "name": "Symantec Legacy Roots (GeoTrust, Thawte, RapidSSL)",
        "status": "distrusted",
        "severity": "critical",
        "description": "Distrusted by Google and Mozilla following repeated misissuance of 30,000+ unauthorized certificates.",
        "advisory": "https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec-ca.html",
    },
}

KNOWN_CA_INCIDENTS: Dict[str, Dict[str, Any]] = {
    "trustcor": {
        "name": "TrustCor Systems",
        "incident_type": "surveillance_ties",
        "severity": "critical",
        "description": "Mozilla, Google, and Apple revoked root inclusion in 2022 after investigations linked the CA to government spyware and surveillance software.",
        "advisory": "https://www.washingtonpost.com/technology/2022/11/08/trustcor-internet-certificates/",
    },
    "darkmatter": {
        "name": "DarkMatter LLC",
        "incident_type": "surveillance_ties",
        "severity": "critical",
        "description": "Denied root inclusion by Mozilla following discovery of offensive cyber-espionage and surveillance operations (Project Raven).",
        "advisory": "https://blog.mozilla.org/security/2019/07/09/treating-darkmatter-as-an-untrusted-ca/",
    },
    "e-tugra": {
        "name": "E-Tugra EBG Bilisim",
        "incident_type": "misissuance",
        "severity": "high",
        "description": "Sub-CA private key compromise and unauthorized test certificates resulted in distrust proceedings and strict monitoring.",
        "advisory": "https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0vPqW-k5F5g",
    },
    "certisign": {
        "name": "Certisign Autorizadora Certificadora",
        "incident_type": "misissuance",
        "severity": "medium",
        "description": "Subject to compliance audits following multiple non-compliant intermediate and OCSP certificate issuances.",
        "advisory": "https://bugzilla.mozilla.org/show_bug.cgi?id=1455581",
    },
}

FREE_AUTOMATED_CAS: Set[str] = {
    "let's encrypt",
    "zerossl",
    "cpanel, inc.",
    "cloudflare, inc.",
    "buypass go ssl",
    "trustcor",
    "gts ca",  # Google Trust Services free automated DV
}


# ---------------------------------------------------------------------------
# ROCA (CVE-2017-15361) INFINEON RSA FACTORABLE KEY CHECK
# ---------------------------------------------------------------------------

# Precomputed prime moduli and fingerprint masks for ROCA detection
# A public modulus N generated by flawed Infineon RSA chips satisfies N % P in allowed_remainders for all test primes
_ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]


def is_roca_vulnerable(n: int) -> bool:
    """
    Checks if an RSA modulus n exhibits the structural fingerprint of
    CVE-2017-15361 (Return of Coppersmith's Attack / Infineon RSA flaw).
    Keys vulnerable to ROCA can be factored orders of magnitude faster.
    """
    if n <= 0 or n % 2 == 0:
        return False

    # In ROCA, Infineon primes p, q were constructed as: k * M + (65537^a mod M)
    # Testing known prime divisors 3, 5, 7, 11, etc.
    # If n mod P does not belong to the powers of 65537 mod P, it CANNOT be ROCA.
    for p in _ROCA_PRIMES:
        # Generate valid powers of 65537 mod p
        base = 65537 % p
        valid_powers = set()
        val = 1
        for _ in range(p):
            valid_powers.add(val)
            val = (val * base) % p

        # In ROCA, N = p * q, where p % P and q % P are powers of 65537 % P
        # Therefore, N % P must also be a product of two powers of 65537 % P
        valid_n_mod_p = set()
        for p1 in valid_powers:
            for p2 in valid_powers:
                valid_n_mod_p.add((p1 * p2) % p)

        if (n % p) not in valid_n_mod_p:
            return False

    return True


# ---------------------------------------------------------------------------
# CA TRUST & INCIDENT EVALUATOR
# ---------------------------------------------------------------------------

def check_ca_trust(
    issuer_str: str,
    subject_str: str = "",
) -> Tuple[str, Optional[Dict[str, Any]], Optional[ContentFindingSchema]]:
    """
    Evaluates Certificate Authority trust against distrusted root stores and incident databases.
    Returns (ca_trust_status, incident_info, finding).
    """
    issuer_lower = issuer_str.lower()
    subject_lower = subject_str.lower()

    # 1. Check for Self-Signed certificate
    if subject_str and subject_str == issuer_str:
        finding = ContentFindingSchema(
            category="tls_certificate",
            title="Self-Signed SSL/TLS Certificate Detected",
            severity="critical",
            confidence=0.99,
            description="The certificate is self-signed and not issued by a globally recognized Certificate Authority. Identity cannot be validated.",
            evidence={"subject": subject_str, "issuer": issuer_str},
            recommendation="Do not trust self-signed certificates on external internet portals.",
            risk_points=30,
        )
        return "self_signed", None, finding

    # 2. Check Distrusted Root CAs
    for key, data in DISTRUSTED_CAS.items():
        if key in issuer_lower:
            incident_info = {
                "ca_name": data["name"],
                "incident_type": "distrusted",
                "severity": data["severity"],
                "description": data["description"],
                "advisory": data["advisory"],
            }
            finding = ContentFindingSchema(
                category="tls_certificate",
                title=f"Untrusted or Revoked Certificate Authority ({data['name']})",
                severity="critical",
                confidence=0.99,
                description=f"The certificate was issued by {data['name']}. {data['description']}",
                evidence={"issuer": issuer_str, "advisory": data["advisory"]},
                recommendation="Do not enter credentials or sensitive details. Browsers block connections to this CA.",
                risk_points=35,
            )
            return "distrusted", incident_info, finding

    # 3. Check Known CA Trust Incidents (e.g. TrustCor, e-Tugra, DarkMatter)
    for key, data in KNOWN_CA_INCIDENTS.items():
        if key in issuer_lower:
            incident_info = {
                "ca_name": data["name"],
                "incident_type": data["incident_type"],
                "severity": data["severity"],
                "description": data["description"],
                "advisory": data["advisory"],
            }
            finding = ContentFindingSchema(
                category="tls_certificate",
                title=f"CA Involved in Known Trust Incident ({data['name']})",
                severity=data["severity"],
                confidence=0.95,
                description=f"The certificate issuer {data['name']} has been flagged for trust violations: {data['description']}",
                evidence={"issuer": issuer_str, "incident_type": data["incident_type"], "advisory": data["advisory"]},
                recommendation="Review the advisory. Avoid transmitting sensitive information on domains utilizing flagged CAs.",
                risk_points=25,
            )
            return "incident_flagged", incident_info, finding

    return "trusted", None, None


# ---------------------------------------------------------------------------
# CRYPTOGRAPHIC KEY GENERATION & STRENGTH AUDIT
# ---------------------------------------------------------------------------

def check_weak_key_generation(
    public_key: Any,
) -> Tuple[bool, Optional[ContentFindingSchema]]:
    """
    Audits the public key for weak key sizes, deprecated algorithms (DSA),
    weak elliptic curves, and factorable key-generation bugs (ROCA CVE-2017-15361).
    Returns (is_weak_key, finding).
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        n = public_key.public_numbers().n

        # A. Key size < 2048
        if key_size < 2048:
            return True, ContentFindingSchema(
                category="tls_certificate",
                title=f"Weak RSA Public Key Size ({key_size}-bit)",
                severity="high",
                confidence=0.98,
                description=f"The certificate uses a {key_size}-bit RSA key. Modern standards mandate a minimum of 2048 bits.",
                evidence={"key_size": key_size},
                recommendation="Re-issue certificate with at least 2048-bit RSA or ECDSA (secp256r1).",
                risk_points=25,
            )

        # B. ROCA / Infineon RSA factorable flaw (CVE-2017-15361)
        if is_roca_vulnerable(n):
            return True, ContentFindingSchema(
                category="tls_certificate",
                title="ROCA Factorable RSA Key Detected (CVE-2017-15361)",
                severity="critical",
                confidence=0.99,
                description="The RSA public key exhibits the Infineon ROCA mathematical defect. Attackers can factor the private key using Coppersmith's attack.",
                evidence={"key_size": key_size, "vulnerability": "CVE-2017-15361 / ROCA"},
                recommendation="Immediately revoke and re-generate the private key using an unaffected cryptographic library.",
                risk_points=35,
            )

    elif isinstance(public_key, dsa.DSAPublicKey):
        return True, ContentFindingSchema(
            category="tls_certificate",
            title="Deprecated Digital Signature Algorithm (DSA) Key",
            severity="high",
            confidence=0.95,
            description="The certificate employs DSA, which is deprecated in modern TLS protocol specifications.",
            evidence={"public_key_type": "DSA"},
            recommendation="Upgrade to RSA 2048+ or ECDSA / Ed25519.",
            risk_points=20,
        )

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_size = public_key.curve.key_size
        if curve_size < 256:
            return True, ContentFindingSchema(
                category="tls_certificate",
                title=f"Weak Elliptic Curve Key Size ({curve_size}-bit)",
                severity="high",
                confidence=0.95,
                description=f"The certificate uses a {curve_size}-bit EC curve. Minimum recommended curve size is 256 bits.",
                evidence={"curve_name": public_key.curve.name, "curve_size": curve_size},
                recommendation="Use NIST P-256 (secp256r1) or P-384.",
                risk_points=20,
            )

    return False, None


def get_all_distrusted_and_incident_cas() -> List[Dict[str, Any]]:
    """Returns a consolidated list of distrusted and incident-flagged CAs."""
    records = []
    for k, v in DISTRUSTED_CAS.items():
        records.append({
            "ca_name": v["name"],
            "incident_type": "distrusted",
            "severity": v["severity"],
            "description": v["description"],
            "advisory_url": v["advisory"],
        })
    for k, v in KNOWN_CA_INCIDENTS.items():
        records.append({
            "ca_name": v["name"],
            "incident_type": v["incident_type"],
            "severity": v["severity"],
            "description": v["description"],
            "advisory_url": v["advisory"],
        })
    return records
