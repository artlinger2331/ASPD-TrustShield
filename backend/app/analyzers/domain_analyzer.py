"""
TrustShield Domain & DNS Infrastructure Analyzer
Passively inspects DNS architecture, MX records, SPF/DMARC email security,
newly registered domain age (NRD), high-abuse TLDs, and dynamic DNS cloaking.
"""

import inspect
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set, Union

import dns.resolver
import dns.exception
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.url_normalizer import extract_domain_parts
from app.models.scan_finding import ScanFinding
from app.schemas.content_analysis import ContentFindingSchema
from app.schemas.domain_analysis import (
    SPFSummary,
    DMARCSummary,
    EmailSecuritySummary,
    DomainAgeSummary,
    DomainAnalysisResult,
)

# ---------------------------------------------------------------------------
# REPUTATION & ABUSE DICTIONARIES
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: Set[str] = {
    "top", "xyz", "click", "buzz", "country", "gq", "cf", "ml", "tk", "ga",
    "work", "rest", "icu", "sbs", "cfd", "monster", "fit", "loan", "stream",
    "cam", "live", "link", "bid", "racing", "win", "date", "faith", "review",
}

DYNAMIC_DNS_DOMAINS: Set[str] = {
    "duckdns.org",
    "no-ip.com",
    "noip.com",
    "ddns.net",
    "zapto.org",
    "ngrok.io",
    "ngrok-free.app",
    "loca.lt",
    "trycloudflare.com",
    "serveo.net",
    "pagekite.me",
    "hopto.org",
    "myftp.biz",
    "bounceme.net",
}

URL_SHORTENERS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "goo.gl",
    "tr.im",
}

KNOWN_CDN_NS_KEYWORDS: Set[str] = {
    "cloudflare", "akamai", "awsdns", "cloudfront", "fastly", "azure-dns",
    "googledomains", "googlecloud", "dynect", "nsone",
}


# ---------------------------------------------------------------------------
# DNS QUERY ENGINE (PASSIVE & RESILIENT)
# ---------------------------------------------------------------------------

def create_resolver(timeout: float = 1.5) -> dns.resolver.Resolver:
    """
    Creates a configured DNS resolver with strict timeouts to prevent hanging.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2.0
    return resolver


def query_dns_records(domain: str, resolver: Optional[dns.resolver.Resolver] = None) -> Dict[str, List[str]]:
    """
    Queries standard DNS records: A, AAAA, MX, NS, and TXT.
    Returns a dictionary of record lists.
    """
    if resolver is None:
        resolver = create_resolver()

    records: Dict[str, List[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
    }

    # Query A (IPv4)
    try:
        answers = resolver.resolve(domain, "A")
        records["A"] = [str(r.address) for r in answers]
    except Exception:
        pass

    # Query AAAA (IPv6)
    try:
        answers = resolver.resolve(domain, "AAAA")
        records["AAAA"] = [str(r.address) for r in answers]
    except Exception:
        pass

    # Query MX (Mail Exchange)
    try:
        answers = resolver.resolve(domain, "MX")
        records["MX"] = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
    except Exception:
        pass

    # Query NS (Name Servers)
    try:
        answers = resolver.resolve(domain, "NS")
        records["NS"] = [str(r.target).rstrip(".") for r in answers]
    except Exception:
        pass

    # Query TXT
    try:
        answers = resolver.resolve(domain, "TXT")
        records["TXT"] = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except Exception:
        pass

    return records


def query_dmarc_record(base_domain: str, resolver: Optional[dns.resolver.Resolver] = None) -> Optional[str]:
    """
    Queries _dmarc.{base_domain} for TXT records containing v=DMARC1.
    """
    if resolver is None:
        resolver = create_resolver()

    dmarc_domain = f"_dmarc.{base_domain}"
    try:
        answers = resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            txt_str = b"".join(r.strings).decode("utf-8", errors="replace")
            if "v=dmarc1" in txt_str.lower():
                return txt_str
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# EMAIL SECURITY PARSER (SPF & DMARC)
# ---------------------------------------------------------------------------

def parse_spf(txt_records: List[str]) -> SPFSummary:
    """
    Extracts and evaluates the SPF record from domain TXT records.
    """
    summary = SPFSummary()

    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            summary.has_spf = True
            summary.raw_record = txt

            # Inspect terminating mechanism
            parts = txt.lower().split()
            for part in parts:
                if part in ("-all", "~all", "?all", "+all"):
                    summary.mechanism_all = part
                    if part == "+all":
                        summary.is_permissive = True
                        summary.details = "Critical: SPF uses '+all' which explicitly allows any server on the internet to send mail for this domain."
                    elif part == "?all":
                        summary.is_permissive = True
                        summary.details = "Warning: SPF uses '?all' (neutral), allowing unauthenticated emails without enforcement."
                    elif part == "~all":
                        summary.details = "SPF uses '~all' (SoftFail). Legitimate messages are signed, but untrusted mail is flagged rather than rejected."
                    elif part == "-all":
                        summary.details = "SPF is strictly configured with '-all' (HardFail) which instructs receivers to reject unauthorized mail."
                    break

            if not summary.details:
                summary.details = f"SPF record configured: {txt[:60]}"
            break

    if not summary.has_spf:
        summary.details = "No SPF record found. Domain has no published sender policy, leaving it vulnerable to email spoofing."

    return summary


def parse_dmarc(raw_dmarc: Optional[str]) -> DMARCSummary:
    """
    Parses and evaluates a DMARC TXT record.
    """
    summary = DMARCSummary()

    if not raw_dmarc:
        summary.has_dmarc = False
        summary.details = "No DMARC policy found. Without DMARC, receiving mail servers cannot verify SPF/DKIM alignment."
        return summary

    summary.has_dmarc = True
    summary.raw_record = raw_dmarc

    # Extract policy p=...
    match = re.search(r"\bp=([a-zA-Z]+)", raw_dmarc)
    if match:
        policy = match.group(1).lower()
        summary.policy = policy
        if policy in ("reject", "quarantine"):
            summary.is_enforced = True
            summary.details = f"DMARC policy is actively enforced ({policy}). Spoofed emails will be blocked or quarantined."
        elif policy == "none":
            summary.is_enforced = False
            summary.details = "DMARC policy is set to 'none' (monitoring only). Spoofed emails are delivered without rejection."
        else:
            summary.details = f"DMARC policy is set to '{policy}'."
    else:
        summary.details = "DMARC record present but missing 'p=' policy directive."

    return summary


# ---------------------------------------------------------------------------
# MAIN DOMAIN ANALYSIS ENGINE
# ---------------------------------------------------------------------------

def analyze_domain(
    domain: str,
    dns_records: Optional[Dict[str, List[str]]] = None,
    raw_dmarc: Optional[str] = None,
    whois_data: Optional[Dict[str, Any]] = None,
    resolve_live: bool = True,
) -> DomainAnalysisResult:
    """
    Executes domain reputation and DNS infrastructure checks.
    Extracts A, AAAA, MX, NS, and email security postures (SPF/DMARC),
    evaluates TLD abuse, dynamic DNS, and newly registered domain (NRD) age.
    """
    domain_clean = domain.strip().lower().strip(".")
    base_domain, subdomain, tld = extract_domain_parts(domain_clean)

    findings: List[ContentFindingSchema] = []
    total_risk_points = 0

    # 1. High-Abuse TLD Detection
    is_suspicious_tld = tld.lower() in SUSPICIOUS_TLDS
    if is_suspicious_tld:
        risk_pts = 10
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="domain_infrastructure",
                title=f"High-Abuse Top-Level Domain (TLD) Detected (.{tld})",
                severity="medium",
                confidence=0.85,
                description=(
                    f"The domain uses the '.{tld}' TLD, which is statistically over-represented in "
                    "low-cost throwaway phishing, scam, and malware delivery campaigns."
                ),
                evidence={"tld": tld, "domain": domain_clean},
                recommendation="Exercise caution when submitting credentials or financial details on budget generic TLDs.",
                risk_points=risk_pts,
            )
        )

    # 2. Dynamic DNS & URL Shortener Cloaking
    is_ddns = any(domain_clean == d or domain_clean.endswith(f".{d}") for d in DYNAMIC_DNS_DOMAINS)
    is_shortener = any(domain_clean == s or domain_clean.endswith(f".{s}") for s in URL_SHORTENERS)

    if is_ddns:
        risk_pts = 20
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="domain_infrastructure",
                title="Dynamic DNS or Reverse Tunnel Service Detected",
                severity="high",
                confidence=0.92,
                description=(
                    f"The host '{domain_clean}' is hosted on a free Dynamic DNS or reverse tunneling service. "
                    "Attackers frequently abuse dynamic DNS to host ephemeral phishing portals on residential IP connections."
                ),
                evidence={"domain": domain_clean, "service_type": "dynamic_dns"},
                recommendation="Legitimate institutions and banks do not host official customer portals on dynamic DNS services.",
                risk_points=risk_pts,
            )
        )

    if is_shortener:
        risk_pts = 15
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="domain_infrastructure",
                title="URL Shortener / Redirection Cloaking Detected",
                severity="medium",
                confidence=0.90,
                description=(
                    f"The domain '{domain_clean}' is a URL shortening service. Shorteners obscure the true destination "
                    "and are frequently leveraged in SMS (smishing) and email phishing lures."
                ),
                evidence={"domain": domain_clean, "service_type": "url_shortener"},
                recommendation="Expand the short link to view the final destination before logging in.",
                risk_points=risk_pts,
            )
        )

    # 3. DNS Telemetry Gathering (Live or Provided)
    if dns_records is None and resolve_live:
        dns_records = query_dns_records(domain_clean)
        if raw_dmarc is None:
            raw_dmarc = query_dmarc_record(base_domain)
    elif dns_records is None:
        dns_records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}

    ip_addresses = dns_records.get("A", []) + dns_records.get("AAAA", [])
    name_servers = dns_records.get("NS", [])
    mx_records = dns_records.get("MX", [])
    txt_records = dns_records.get("TXT", [])

    # 4. Email Security Assessment (SPF & DMARC)
    spf = parse_spf(txt_records)
    dmarc = parse_dmarc(raw_dmarc)

    has_mx = len(mx_records) > 0
    spoofing_risk = "none"

    if has_mx and not spf.has_spf:
        spoofing_risk = "high"
        risk_pts = 10
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="dns_security",
                title="Missing SPF Email Authentication Record",
                severity="medium",
                confidence=0.88,
                description="This domain has active mail servers (MX) but lacks an SPF record. Attackers can forge emails from this domain.",
                evidence={"mx_records": mx_records, "spf_status": "missing"},
                recommendation="Configure an SPF TXT record specifying authorized mail outbound servers.",
                risk_points=risk_pts,
            )
        )
    elif spf.has_spf and spf.is_permissive:
        risk_pts = 10
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="dns_security",
                title=f"Permissive SPF Record ({spf.mechanism_all})",
                severity="medium",
                confidence=0.85,
                description=spf.details or "SPF policy is overly permissive.",
                evidence={"raw_spf": spf.raw_record, "mechanism": spf.mechanism_all},
                recommendation="Tighten SPF to use '~all' or '-all' to prevent unauthorized email origination.",
                risk_points=risk_pts,
            )
        )

    if has_mx and not dmarc.has_dmarc:
        risk_pts = 10
        total_risk_points += risk_pts
        findings.append(
            ContentFindingSchema(
                category="dns_security",
                title="Missing DMARC Email Security Policy",
                severity="medium",
                confidence=0.88,
                description="The domain lacks a DMARC policy at _dmarc." + base_domain + ". Receivers cannot verify email authenticity.",
                evidence={"base_domain": base_domain, "dmarc_status": "missing"},
                recommendation="Deploy a DMARC record starting with 'p=quarantine' or 'p=reject' to protect your domain reputation.",
                risk_points=risk_pts,
            )
        )
    elif dmarc.has_dmarc and not dmarc.is_enforced:
        findings.append(
            ContentFindingSchema(
                category="dns_security",
                title="DMARC Policy Not Enforced (p=none)",
                severity="low",
                confidence=0.80,
                description="DMARC policy is set to 'p=none' (reporting mode only). Unauthorized emails spoofing this domain are still delivered.",
                evidence={"raw_dmarc": dmarc.raw_record, "policy": dmarc.policy},
                recommendation="Upgrade DMARC policy to 'p=quarantine' or 'p=reject' to actively block domain impersonation.",
                risk_points=5,
            )
        )

    email_sec = EmailSecuritySummary(
        has_mx=has_mx,
        mx_servers=mx_records,
        spf=spf,
        dmarc=dmarc,
        spoofing_risk_level=spoofing_risk,
    )

    # 5. Newly Registered Domain (NRD) Assessment
    domain_age: Optional[DomainAgeSummary] = None
    if whois_data:
        creation_date = whois_data.get("creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            is_nrd = age_days <= 30

            domain_age = DomainAgeSummary(
                creation_date=creation_date,
                age_days=age_days,
                is_newly_registered=is_nrd,
                registrar=whois_data.get("registrar"),
            )

            if age_days <= 7:
                risk_pts = 25
                total_risk_points += risk_pts
                findings.append(
                    ContentFindingSchema(
                        category="domain_infrastructure",
                        title=f"Critical: Newly Registered Domain ({age_days} Days Old)",
                        severity="critical",
                        confidence=0.95,
                        description=(
                            f"The domain '{domain_clean}' was registered only {age_days} days ago. "
                            "Over 70% of malicious phishing and scam campaigns utilize throwaway domains registered within the past week."
                        ),
                        evidence={
                            "domain": domain_clean,
                            "creation_date": creation_date.isoformat(),
                            "age_days": age_days,
                            "registrar": whois_data.get("registrar"),
                        },
                        recommendation="Do NOT trust newly created websites with confidential personal or banking credentials.",
                        risk_points=risk_pts,
                    )
                )
            elif age_days <= 30:
                risk_pts = 15
                total_risk_points += risk_pts
                findings.append(
                    ContentFindingSchema(
                        category="domain_infrastructure",
                        title=f"Recently Registered Domain ({age_days} Days Old)",
                        severity="high",
                        confidence=0.90,
                        description=(
                            f"The domain '{domain_clean}' was registered {age_days} days ago. "
                            "Legitimate banking, institutional, and enterprise services have years of domain registration history."
                        ),
                        evidence={
                            "domain": domain_clean,
                            "creation_date": creation_date.isoformat(),
                            "age_days": age_days,
                            "registrar": whois_data.get("registrar"),
                        },
                        recommendation="Verify the authenticity of recent domains before submitting data.",
                        risk_points=risk_pts,
                    )
                )

    # 6. Overall Severity & Synthesis
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

    if total_risk_points >= 40:
        summary = f"High Risk: Suspicious domain infrastructure identified with {len(findings)} negative indicators."
    elif total_risk_points > 0:
        summary = f"Elevated Risk: Found {len(findings)} domain or DNS configuration issues."
    else:
        summary = "Domain and DNS infrastructure appear legitimate with established DNS architecture."

    return DomainAnalysisResult(
        domain=domain_clean,
        base_domain=base_domain,
        tld=tld,
        is_suspicious_tld=is_suspicious_tld,
        is_ddns_or_shortener=is_ddns or is_shortener,
        dns_records=dns_records,
        name_servers=name_servers,
        ip_addresses=ip_addresses,
        email_security=email_sec,
        domain_age=domain_age,
        total_risk_points=total_risk_points,
        max_severity=max_sev,
        summary=summary,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE FOR DOMAIN FINDINGS
# ---------------------------------------------------------------------------

def save_domain_findings_to_db_sync(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Session,
) -> List[ScanFinding]:
    """
    Synchronously persists domain & DNS findings into the `scan_findings` table.
    """
    db_records: List[ScanFinding] = []
    for f in findings:
        record = ScanFinding(
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
        db.add(record)
        db_records.append(record)

    db.commit()
    for record in db_records:
        db.refresh(record)

    return db_records


async def save_domain_findings_to_db(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Any,
) -> List[ScanFinding]:
    """
    Asynchronously persists domain & DNS findings into the `scan_findings` table.
    Supports both AsyncSession and sync fallback wrappers.
    """
    db_records: List[ScanFinding] = []
    for f in findings:
        record = ScanFinding(
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
        db.add(record)
        db_records.append(record)

    commit_res = db.commit()
    if inspect.isawaitable(commit_res):
        await commit_res

    for record in db_records:
        refresh_res = db.refresh(record)
        if inspect.isawaitable(refresh_res):
            await refresh_res

    return db_records

