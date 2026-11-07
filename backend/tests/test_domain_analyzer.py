"""
Unit tests for Domain and DNS Infrastructure Analyzer.
"""

from datetime import datetime, timezone, timedelta
import pytest

from app.analyzers.domain_analyzer import (
    analyze_domain,
    parse_spf,
    parse_dmarc,
    save_domain_findings_to_db_sync,
)
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.db.session import local_session_factory


def test_suspicious_tld_detection():
    """Verify high-abuse TLDs (.top, .xyz, .click) are flagged with risk points."""
    # Suspicious .top TLD
    res_top = analyze_domain("secure-banking-update.top", resolve_live=False)
    assert res_top.is_suspicious_tld is True
    assert res_top.total_risk_points >= 10
    assert any("High-Abuse Top-Level Domain" in f.title for f in res_top.findings)

    # Suspicious .xyz TLD
    res_xyz = analyze_domain("claim-crypto-airdrop.xyz", resolve_live=False)
    assert res_xyz.is_suspicious_tld is True
    assert any("High-Abuse Top-Level Domain" in f.title for f in res_xyz.findings)

    # Legitimate standard .com and multi-part .co.in
    res_com = analyze_domain("google.com", resolve_live=False)
    assert res_com.is_suspicious_tld is False

    res_in = analyze_domain("sbi.co.in", resolve_live=False)
    assert res_in.is_suspicious_tld is False


def test_dynamic_dns_and_shorteners():
    """Verify detection of free DDNS providers and URL redirection shorteners."""
    # Dynamic DNS (duckdns.org)
    res_ddns = analyze_domain("malicious-payload.duckdns.org", resolve_live=False)
    assert res_ddns.is_ddns_or_shortener is True
    assert any("Dynamic DNS" in f.title for f in res_ddns.findings)
    assert res_ddns.total_risk_points >= 20

    # Reverse Tunnel (ngrok)
    res_ngrok = analyze_domain("phish-login.ngrok-free.app", resolve_live=False)
    assert res_ngrok.is_ddns_or_shortener is True
    assert any("Dynamic DNS or Reverse Tunnel" in f.title for f in res_ngrok.findings)

    # URL Shortener (bit.ly)
    res_short = analyze_domain("bit.ly", resolve_live=False)
    assert res_short.is_ddns_or_shortener is True
    assert any("URL Shortener" in f.title for f in res_short.findings)


def test_email_security_spf_evaluation():
    """Verify SPF policy extraction and permissive mechanism detection."""
    # 1. Hardened SPF with -all
    spf_hard = parse_spf(["v=spf1 include:_spf.google.com ~all", "other=txt"])
    assert spf_hard.has_spf is True
    assert spf_hard.mechanism_all == "~all"
    assert spf_hard.is_permissive is False

    # 2. Permissive +all allows any host
    spf_perm = parse_spf(["v=spf1 ip4:1.2.3.4 +all"])
    assert spf_perm.has_spf is True
    assert spf_perm.is_permissive is True
    assert spf_perm.mechanism_all == "+all"

    # 3. Missing SPF
    spf_missing = parse_spf(["google-site-verification=abc"])
    assert spf_missing.has_spf is False


def test_email_security_dmarc_evaluation():
    """Verify DMARC policy parsing (reject, quarantine, none, missing)."""
    # 1. Enforced reject
    dmarc_rej = parse_dmarc("v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@bank.com")
    assert dmarc_rej.has_dmarc is True
    assert dmarc_rej.is_enforced is True
    assert dmarc_rej.policy == "reject"

    # 2. Enforced quarantine
    dmarc_quar = parse_dmarc("v=DMARC1; p=quarantine; pct=100")
    assert dmarc_quar.has_dmarc is True
    assert dmarc_quar.is_enforced is True
    assert dmarc_quar.policy == "quarantine"

    # 3. Not enforced (p=none)
    dmarc_none = parse_dmarc("v=DMARC1; p=none; rua=mailto:reports@test.com")
    assert dmarc_none.has_dmarc is True
    assert dmarc_none.is_enforced is False
    assert dmarc_none.policy == "none"

    # 4. Missing DMARC
    dmarc_none_raw = parse_dmarc(None)
    assert dmarc_none_raw.has_dmarc is False
    assert dmarc_none_raw.is_enforced is False


def test_newly_registered_domain_age():
    """Verify that domain registration age <= 7 and <= 30 days triggers NRD alerts."""
    now = datetime.now(timezone.utc)

    # 1. Ultra-new domain (3 days old) -> Critical NRD
    whois_3d = {
        "creation_date": now - timedelta(days=3),
        "registrar": "NameCheap, Inc.",
    }
    res_3d = analyze_domain("sbi-kyc-verify.top", whois_data=whois_3d, resolve_live=False)
    assert res_3d.domain_age.is_newly_registered is True
    assert res_3d.domain_age.age_days == 3
    assert any("Newly Registered Domain" in f.title and f.severity == "critical" for f in res_3d.findings)

    # 2. Recent domain (20 days old) -> High NRD
    whois_20d = {
        "creation_date": now - timedelta(days=20),
        "registrar": "GoDaddy",
    }
    res_20d = analyze_domain("portal-update.com", whois_data=whois_20d, resolve_live=False)
    assert res_20d.domain_age.is_newly_registered is True
    assert any("Recently Registered Domain" in f.title and f.severity == "high" for f in res_20d.findings)

    # 3. Established domain (500 days old) -> No NRD alert
    whois_old = {
        "creation_date": now - timedelta(days=500),
        "registrar": "MarkMonitor",
    }
    res_old = analyze_domain("paypal.com", whois_data=whois_old, resolve_live=False)
    assert res_old.domain_age.is_newly_registered is False
    assert not any("Registered Domain" in f.title for f in res_old.findings)


def test_domain_analysis_synthesis_and_db_persistence():
    """Verify end-to-end domain analysis combining DNS, TLD, SPF, and database persistence."""
    session = local_session_factory()
    try:
        # Create parent scan
        scan = Scan(
            input_url="https://sbi-portal-verify.top/login",
            normalized_url="https://sbi-portal-verify.top/login",
            status="running",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # Mocked DNS responses with active mail server but missing SPF & DMARC on a .top domain
        mock_dns = {
            "A": ["185.120.45.10"],
            "AAAA": [],
            "MX": ["10 mail.sbi-portal-verify.top"],
            "NS": ["ns1.hostinger.com", "ns2.hostinger.com"],
            "TXT": [],  # Missing SPF
        }

        mock_whois = {
            "creation_date": datetime.now(timezone.utc) - timedelta(days=4),
            "registrar": "Hostinger, UAB",
        }

        result = analyze_domain(
            domain="sbi-portal-verify.top",
            dns_records=mock_dns,
            raw_dmarc=None,  # Missing DMARC
            whois_data=mock_whois,
            resolve_live=False,
        )

        assert result.is_suspicious_tld is True
        assert result.domain_age.is_newly_registered is True
        assert result.email_security.has_mx is True
        assert result.email_security.spf.has_spf is False
        assert len(result.findings) >= 3

        # Persist domain findings to database
        saved = save_domain_findings_to_db_sync(
            scan_id=scan.id,
            findings=result.findings,
            db=session,
        )

        assert len(saved) == len(result.findings)

        # Verify findings in database
        db_findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        assert len(db_findings) == len(result.findings)
        categories = {f.category for f in db_findings}
        assert "domain_infrastructure" in categories
        assert "dns_security" in categories

        for f in db_findings:
            assert f.scan_id == scan.id
            assert f.risk_points > 0
            assert f.severity in ("critical", "high", "medium", "low")
    finally:
        session.close()
