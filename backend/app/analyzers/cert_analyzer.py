"""
TrustShield SSL/TLS Certificate & CA Trust Analyzer
Extracts X.509 certificate telemetry over passive TLS handshakes,
verifies validity windows, SAN matching, issuer reputation, CT logs,
and detects free automated certificates on brand lookalikes.
"""

import inspect
import re
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Set, Union
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.certificate import Certificate
from app.models.scan_finding import ScanFinding
from app.schemas.content_analysis import ContentFindingSchema
from app.schemas.certificate import (
    CertificateChainNode,
    CertificateAnalysisResult,
)

# ---------------------------------------------------------------------------
# CA REPUTATION & OID CONSTANTS
# ---------------------------------------------------------------------------

FREE_AUTOMATED_CAS: Set[str] = {
    "let's encrypt",
    "zerossl",
    "cpanel, inc.",
    "cloudflare, inc.",
    "buypass go ssl",
    "trustcor",
    "gts ca",  # Google Trust Services free automated DV
}

DISTRUSTED_CAS: Set[str] = {
    "wosign",
    "startcom",
    "cnnic",
    "symantec",  # Distrusted legacy roots
    "diginotar",
}

PRECERT_SCT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


# ---------------------------------------------------------------------------
# PASSIVE TLS HANDSHAKE & DER ACQUISITION
# ---------------------------------------------------------------------------

def fetch_server_certificate(
    host: str,
    port: int = 443,
    timeout: float = 2.5,
) -> Tuple[Optional[bytes], bool, Optional[str]]:
    """
    Passively connects over TLS (port 443) and extracts the peer certificate DER bytes.
    Returns (der_bytes, chain_valid, error_reason).
    If verification fails (e.g. self-signed or expired), gracefully falls back
    to an unverified context to inspect and explain the certificate flaw.
    """
    clean_host = host.strip("[]").lower()
    chain_valid = False
    der_bytes: Optional[bytes] = None
    error_reason: Optional[str] = None

    # 1. Attempt verified handshake first
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                der_bytes = ssock.getpeercert(binary_form=True)
                chain_valid = True
                return der_bytes, chain_valid, None
    except ssl.SSLCertVerificationError as cert_err:
        error_reason = f"Verification failed: {cert_err.verify_message}"
        chain_valid = False
    except (socket.timeout, TimeoutError):
        return None, False, f"Connection timed out while connecting to {clean_host}:{port}"
    except (socket.gaierror, ConnectionRefusedError, OSError) as net_err:
        return None, False, f"Failed to connect to {clean_host}:{port} ({str(net_err)})"

    # 2. Fallback to unverified context to inspect offending certificate
    unverified_ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with unverified_ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                der_bytes = ssock.getpeercert(binary_form=True)
    except Exception:
        pass

    return der_bytes, chain_valid, error_reason


# ---------------------------------------------------------------------------
# X.509 CERTIFICATE TELEMETRY EXTRACTOR
# ---------------------------------------------------------------------------

def parse_x509_certificate(
    der_bytes: bytes,
    target_domain: str,
    chain_valid_default: bool = True,
    chain_error: Optional[str] = None,
) -> CertificateAnalysisResult:
    """
    Parses raw DER certificate bytes using cryptography and generates structured telemetry.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as e:
        return CertificateAnalysisResult(
            https=False,
            is_valid=False,
            warning=f"Failed to parse X.509 certificate: {str(e)}",
        )

    findings: List[ContentFindingSchema] = []
    total_risk_points = 0
    now = datetime.now(timezone.utc)

    # 1. Subject & Issuer Formatting
    subject_cn = ""
    subject_org = ""
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            subject_cn = str(attr.value)
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            subject_org = str(attr.value)
    subject_str = f"CN={subject_cn}" + (f", O={subject_org}" if subject_org else "")

    issuer_cn = ""
    issuer_org = ""
    for attr in cert.issuer:
        if attr.oid == NameOID.COMMON_NAME:
            issuer_cn = str(attr.value)
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            issuer_org = str(attr.value)
    issuer_str = f"CN={issuer_cn}" + (f", O={issuer_org}" if issuer_org else "")

    # 2. Validity Window & Expiration
    valid_from = cert.not_valid_before_utc
    valid_to = cert.not_valid_after_utc
    days_until_expiry = (valid_to - now).days

    is_expired = now > valid_to
    is_not_yet_valid = now < valid_from
    is_valid_dates = not is_expired and not is_not_yet_valid

    if is_expired:
        risk_pts = 25
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title="SSL/TLS Certificate Has Expired",
                severity="critical",
                confidence=0.98,
                description=f"The certificate expired on {valid_to.strftime('%Y-%m-%d')} ({abs(days_until_expiry)} days ago). Browsers will block access.",
                evidence={"valid_to": valid_to.isoformat(), "days_expired": abs(days_until_expiry)},
                recommendation="Do not proceed or submit sensitive information on sites with expired certificates.",
                risk_points=risk_pts,
            )
        )
    elif is_not_yet_valid:
        risk_pts = 20
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title="SSL/TLS Certificate Not Yet Valid",
                severity="high",
                confidence=0.95,
                description=f"Certificate activation date ({valid_from.strftime('%Y-%m-%d')}) is in the future. Clock skew or illegitimate deployment.",
                evidence={"valid_from": valid_from.isoformat()},
                recommendation="Verify system clock or avoid submitting information.",
                risk_points=risk_pts,
            )
        )
    elif 0 <= days_until_expiry <= 14:
        risk_pts = 10
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title=f"SSL/TLS Certificate Expiring Soon ({days_until_expiry} Days Remaining)",
                severity="medium",
                confidence=0.90,
                description=f"The certificate will expire on {valid_to.strftime('%Y-%m-%d')}. If not renewed, the site will become inaccessible.",
                evidence={"valid_to": valid_to.isoformat(), "days_remaining": days_until_expiry},
                recommendation="Ensure automated certificate renewal (ACME / certbot) is active.",
                risk_points=risk_pts,
            )
        )

    # 3. Subject Alternative Names (SAN) Match
    san_list: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_list = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
    except Exception:
        if subject_cn:
            san_list = [subject_cn]

    def matches_san(domain: str, san_entry: str) -> bool:
        domain = domain.lower().strip(".")
        san_entry = san_entry.lower().strip(".")
        if domain == san_entry:
            return True
        if san_entry.startswith("*."):
            wildcard_suffix = san_entry[2:]
            parts = domain.split(".")
            if len(parts) >= 2:
                parent = ".".join(parts[1:])
                return parent == wildcard_suffix
        return False

    san_matched = any(matches_san(target_domain, san) for san in san_list)
    if not san_matched and san_list:
        risk_pts = 30
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title="SSL Certificate Hostname Mismatch",
                severity="critical",
                confidence=0.98,
                description=(
                    f"The presented certificate was issued for [{', '.join(san_list[:3])}], "
                    f"which does not match the accessed domain '{target_domain}'. "
                    "This strongly indicates credential harvesting, DNS redirection, or MITM interception."
                ),
                evidence={"target_domain": target_domain, "san_list": san_list},
                recommendation="Never enter passwords or confidential data on sites with certificate name mismatches.",
                risk_points=risk_pts,
            )
        )

    # 4. Public Key & Signature Algorithm Verification
    public_key = cert.public_key()
    pub_key_type = "UNKNOWN"
    pub_key_bits: Optional[int] = None
    weak_algo = False

    if isinstance(public_key, rsa.RSAPublicKey):
        pub_key_type = "RSA"
        pub_key_bits = public_key.key_size
        if pub_key_bits < 2048:
            weak_algo = True
            risk_pts = 20
            total_risk_points += risk_pts
            findings.append(
                ContentFindingSchema(
                    category="tls_certificate",
                    title=f"Weak RSA Public Key Size ({pub_key_bits}-bit)",
                    severity="high",
                    confidence=0.95,
                    description=f"The certificate uses a {pub_key_bits}-bit RSA key. Modern standards mandate a minimum of 2048 bits.",
                    evidence={"key_size": pub_key_bits},
                    recommendation="Re-issue certificate with at least 2048-bit RSA or ECDSA (secp256r1).",
                    risk_points=risk_pts,
                )
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        pub_key_type = "ECDSA"
        pub_key_bits = public_key.curve.key_size
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pub_key_type = "EdDSA"

    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid)
    if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        weak_algo = True
        risk_pts = 25
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title=f"Deprecated Cryptographic Signature Algorithm ({sig_algo})",
                severity="critical",
                confidence=0.98,
                description=f"The certificate is signed using {sig_algo}, which is cryptographically broken and vulnerable to collision attacks.",
                evidence={"signature_algorithm": sig_algo},
                recommendation="Replace certificate immediately with SHA-256 or SHA-384 signatures.",
                risk_points=risk_pts,
            )
        )

    # 5. Certificate Authority Trust & Self-Signed Check
    is_self_signed = cert.subject == cert.issuer
    ca_trust_status = "trusted"

    if is_self_signed:
        ca_trust_status = "self_signed"
        risk_pts = 30
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title="Self-Signed SSL/TLS Certificate Detected",
                severity="critical",
                confidence=0.99,
                description="The certificate is self-signed and not issued by a globally recognized Certificate Authority. Identity cannot be validated.",
                evidence={"subject": subject_str, "issuer": issuer_str},
                recommendation="Do not trust self-signed certificates on external internet portals.",
                risk_points=risk_pts,
            )
        )
    else:
        # Check for distrusted CAs
        issuer_lower = issuer_str.lower()
        if any(bad_ca in issuer_lower for bad_ca in DISTRUSTED_CAS):
            ca_trust_status = "distrusted"
            risk_pts = 30
            total_risk_points += risk_pts
            findings.append(
                ContentFindingSchema(
                    category="tls_certificate",
                    title="Untrusted or Revoked Certificate Authority",
                    severity="critical",
                    confidence=0.98,
                    description=f"The certificate was issued by an untrusted CA ({issuer_cn}). Modern root stores have distrusted this issuer.",
                    evidence={"issuer": issuer_str},
                    recommendation="Do not submit credentials on sites with distrusted root authorities.",
                    risk_points=risk_pts,
                )
            )

    # 6. Free Automated Certificate on Brand Target Domain
    is_free_ca = any(free_ca in issuer_str.lower() for free_ca in FREE_AUTOMATED_CAS)
    target_lower = target_domain.lower()
    financial_keywords = ["bank", "secure", "login", "verify", "account", "update", "kyc", "sbi", "hdfc", "paypal", "netflix", "chase"]
    has_target_keyword = any(kw in target_lower for kw in financial_keywords)

    warning_message = None
    if is_free_ca and has_target_keyword and not is_self_signed:
        risk_pts = 15
        total_risk_points += risk_pts
        warning_message = (
            f"Certificate is valid and issued by {issuer_cn}, but domain exhibits banking/financial keywords. "
            "A valid HTTPS certificate only guarantees encryption; it does NOT verify that the site operator is legitimate. "
            "Attackers routinely obtain free automated certificates to impersonate trusted brands."
        )
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title=f"Free Automated DV Certificate on Sensitive/Brand Domain ({issuer_cn})",
                severity="high",
                confidence=0.88,
                description=warning_message,
                evidence={"issuer": issuer_str, "target_domain": target_domain},
                recommendation="Verify the domain against official company portals. A padlock does NOT prove the site is safe.",
                risk_points=risk_pts,
            )
        )

    # 7. Certificate Transparency (CT) Logging Check
    ct_log_present = False
    try:
        cert.extensions.get_extension_for_oid(PRECERT_SCT_OID)
        ct_log_present = True
    except Exception:
        ct_log_present = False

    if not ct_log_present and not is_self_signed:
        findings.append(
            ContentFindingSchema(
                category="tls_certificate",
                title="No Embedded Certificate Transparency (CT) SCTs Detected",
                severity="low",
                confidence=0.80,
                description="The certificate does not embed Signed Certificate Timestamps (SCTs) directly. SCTs may be delivered via TLS extension or OCSP stapling.",
                evidence={"ct_embedded": False},
                recommendation="Enable embedded SCTs or OCSP stapling with SCT delivery.",
                risk_points=5,
            )
        )

    # 8. Certificate Chain Hierarchy
    chain_nodes: List[CertificateChainNode] = [
        CertificateChainNode(
            name=subject_cn or target_domain,
            type="Website Certificate",
            status="valid" if is_valid_dates and san_matched and not is_self_signed else "untrusted",
        ),
        CertificateChainNode(
            name=issuer_cn or "Intermediate CA",
            type="Intermediate CA",
            status="trusted" if ca_trust_status == "trusted" else "untrusted",
        ),
        CertificateChainNode(
            name=issuer_org or "Root CA",
            type="Root CA",
            status="trusted" if ca_trust_status == "trusted" else "untrusted",
        ),
    ]

    # Calculate overall valid flag
    is_valid_overall = (
        is_valid_dates and
        san_matched and
        not is_self_signed and
        ca_trust_status == "trusted" and
        chain_valid_default
    )

    # Overall severity
    severities = [f.severity for f in findings]
    if "critical" in severities:
        max_sev = "critical"
    elif "high" in severities:
        max_sev = "high"
    elif "medium" in severities:
        max_sev = "medium"
    elif "low" in severities:
        max_sev = "low"
    else:
        max_sev = "info"

    raw_cert_summary = {
        "subject": subject_str,
        "issuer": issuer_str,
        "serial_number": hex(cert.serial_number),
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat(),
        "days_until_expiry": days_until_expiry,
        "san_list": san_list,
        "public_key_type": pub_key_type,
        "public_key_bits": pub_key_bits,
        "signature_algorithm": sig_algo,
        "ct_log_present": ct_log_present,
    }

    return CertificateAnalysisResult(
        https=True,
        subject=subject_str,
        issuer=issuer_str,
        serial_number=hex(cert.serial_number),
        signature_algorithm=sig_algo,
        public_key_type=pub_key_type,
        public_key_bits=pub_key_bits,
        valid_from=valid_from,
        valid_to=valid_to,
        days_until_expiry=days_until_expiry,
        is_valid=is_valid_overall,
        is_revoked=False,
        chain_valid=chain_valid_default and not is_self_signed,
        ct_log_present=ct_log_present,
        ca_trust_status=ca_trust_status,
        weak_algo=weak_algo,
        san_matched=san_matched,
        san_list=san_list,
        chain=chain_nodes,
        warning=warning_message or chain_error,
        raw_certificate=raw_cert_summary,
        findings=findings,
        total_risk_points=total_risk_points,
        max_severity=max_sev,
    )


# ---------------------------------------------------------------------------
# MAIN END-TO-END CERTIFICATE ANALYZER
# ---------------------------------------------------------------------------

def analyze_certificate(
    target_url_or_domain: str,
    der_bytes: Optional[bytes] = None,
    resolve_live: bool = True,
    port: int = 443,
) -> CertificateAnalysisResult:
    """
    Main entry point for Certificate Analysis:
    1. Extracts domain from URL or raw hostname.
    2. Performs passive TLS handshake if live resolution requested.
    3. Parses certificate and returns structured telemetry and findings.
    """
    if "://" in target_url_or_domain:
        parsed = urlparse(target_url_or_domain)
        host = parsed.hostname or target_url_or_domain
        port = parsed.port or port
    else:
        host = target_url_or_domain.split(":")[0]

    host = host.strip("[]").lower()

    chain_valid = True
    chain_error = None

    if der_bytes is None and resolve_live:
        der_bytes, chain_valid, chain_error = fetch_server_certificate(host, port=port)

    if der_bytes is None:
        return CertificateAnalysisResult(
            https=False,
            is_valid=False,
            warning=chain_error or f"No SSL/TLS certificate could be retrieved from {host}:{port}.",
            findings=[
                ContentFindingSchema(
                    category="tls_certificate",
                    title="No HTTPS / TLS Encryption Available",
                    severity="high",
                    confidence=0.95,
                    description=f"The server at {host}:{port} does not serve a valid SSL/TLS certificate. Traffic is unencrypted.",
                    evidence={"host": host, "port": port, "error": chain_error},
                    recommendation="Do not submit passwords, card details, or personal data on unencrypted HTTP connections.",
                    risk_points=20,
                )
            ],
            total_risk_points=20,
            max_severity="high",
        )

    return parse_x509_certificate(
        der_bytes=der_bytes,
        target_domain=host,
        chain_valid_default=chain_valid,
        chain_error=chain_error,
    )


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE FOR CERTIFICATES
# ---------------------------------------------------------------------------

def save_certificate_to_db_sync(
    scan_id: uuid.UUID,
    result: CertificateAnalysisResult,
    db: Session,
) -> Optional[Certificate]:
    """
    Synchronously persists certificate details to the `certificates` table
    and appends certificate findings to `scan_findings`.
    """
    if not result.https:
        return None

    # Check for existing certificate record
    cert_record = db.query(Certificate).filter(Certificate.scan_id == scan_id).first()
    if cert_record is None:
        cert_record = Certificate(
            scan_id=scan_id,
            subject=result.subject,
            issuer=result.issuer,
            valid_from=result.valid_from,
            valid_to=result.valid_to,
            days_until_expiry=result.days_until_expiry,
            is_valid=result.is_valid,
            is_revoked=result.is_revoked,
            chain_valid=result.chain_valid,
            ct_log_present=result.ct_log_present,
            ca_trust_status=result.ca_trust_status,
            raw_certificate=result.raw_certificate,
        )
        db.add(cert_record)
    else:
        cert_record.subject = result.subject
        cert_record.issuer = result.issuer
        cert_record.valid_from = result.valid_from
        cert_record.valid_to = result.valid_to
        cert_record.days_until_expiry = result.days_until_expiry
        cert_record.is_valid = result.is_valid
        cert_record.chain_valid = result.chain_valid
        cert_record.ct_log_present = result.ct_log_present
        cert_record.ca_trust_status = result.ca_trust_status
        cert_record.raw_certificate = result.raw_certificate

    # Also persist certificate findings into scan_findings
    for f in result.findings:
        f_record = ScanFinding(
            scan_id=scan_id,
            category=f.category,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            evidence=f.evidence or {},
            recommendation=f.recommendation,
            risk_points=f.risk_points,
            raw_data=f.raw_data or {},
        )
        db.add(f_record)

    db.commit()
    db.refresh(cert_record)
    return cert_record


async def save_certificate_to_db(
    scan_id: uuid.UUID,
    result: CertificateAnalysisResult,
    db: Any,
) -> Optional[Certificate]:
    """
    Asynchronously persists certificate details to the `certificates` table
    and appends certificate findings to `scan_findings`.
    Supports both AsyncSession and sync fallback wrappers.
    """
    if not result.https:
        return None

    cert_record = Certificate(
        scan_id=scan_id,
        subject=result.subject,
        issuer=result.issuer,
        valid_from=result.valid_from,
        valid_to=result.valid_to,
        days_until_expiry=result.days_until_expiry,
        is_valid=result.is_valid,
        is_revoked=result.is_revoked,
        chain_valid=result.chain_valid,
        ct_log_present=result.ct_log_present,
        ca_trust_status=result.ca_trust_status,
        raw_certificate=result.raw_certificate,
    )
    db.add(cert_record)

    for f in result.findings:
        f_record = ScanFinding(
            scan_id=scan_id,
            category=f.category,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            evidence=f.evidence or {},
            recommendation=f.recommendation,
            risk_points=f.risk_points,
            raw_data=f.raw_data or {},
        )
        db.add(f_record)

    commit_res = db.commit()
    if inspect.isawaitable(commit_res):
        await commit_res

    refresh_res = db.refresh(cert_record)
    if inspect.isawaitable(refresh_res):
        await refresh_res

    return cert_record

