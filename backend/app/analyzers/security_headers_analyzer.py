"""
TrustShield Web Security Headers & Passive Configuration Analyzer
Inspects HTTP defense headers (HSTS, CSP, XFO, XCTO, Referrer, Permissions),
cookie security flags (Secure, HttpOnly, SameSite), and server information disclosure.
"""

import inspect
import re
import uuid
from typing import List, Dict, Any, Optional, Tuple, Set, Union
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_finding import ScanFinding
from app.schemas.content_analysis import ContentFindingSchema
from app.schemas.security_headers import (
    SecurityHeaderItem,
    CookieSecurityItem,
    SecurityHeadersAnalysisResult,
)

SAFE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 (TrustShield SecOps Passive Analyzer/1.0)"
)


# ---------------------------------------------------------------------------
# HEADER EVALUATION LOGIC
# ---------------------------------------------------------------------------

def analyze_security_headers(
    headers: Dict[str, str],
    target_url: str,
    cookies_raw: Optional[List[str]] = None,
    is_https: bool = True,
) -> SecurityHeadersAnalysisResult:
    """
    Evaluates HTTP response headers and cookies for defense-in-depth security posture.
    """
    # Normalize headers to lowercase keys
    norm_headers: Dict[str, str] = {k.lower().strip(): v.strip() for k, v in headers.items()}

    headers_evaluated: List[SecurityHeaderItem] = []
    cookies_evaluated: List[CookieSecurityItem] = []
    findings: List[ContentFindingSchema] = []
    tech_disclosures: List[str] = []
    total_risk_points = 0

    # 1. HTTPS Enforcement Check
    if is_https:
        headers_evaluated.append(
            SecurityHeaderItem(
                name="HTTPS Enforcement",
                status="pass",
                detail="Site loads over encrypted HTTPS protocol.",
                value="HTTPS",
            )
        )
    else:
        risk_pts = 15
        total_risk_points += risk_pts
        headers_evaluated.append(
            SecurityHeaderItem(
                name="HTTPS Enforcement",
                status="fail",
                detail="Website serves content over unencrypted plain HTTP.",
                value="HTTP",
            )
        )
        findings.append(
            ContentFindingSchema(
                category="security_headers",
                title="Missing HTTPS Encryption (Plain HTTP)",
                severity="high",
                confidence=0.98,
                description="The website serves traffic unencrypted. Passwords and credentials can be intercepted by network adversaries.",
                evidence={"url": target_url},
                recommendation="Enforce full-site HTTPS encryption with automatic 301 redirection.",
                risk_points=risk_pts,
            )
        )

    # 2. Strict-Transport-Security (HSTS)
    hsts_val = norm_headers.get("strict-transport-security")
    hsts_present = False

    if hsts_val:
        hsts_present = True
        max_age_match = re.search(r"\bmax-age=(\d+)", hsts_val.lower())
        max_age = int(max_age_match.group(1)) if max_age_match else 0

        if max_age >= 15552000:  # >= 180 days
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="HSTS",
                    status="pass",
                    detail=f"HSTS is actively enforced with a strong max-age ({max_age} seconds).",
                    value=hsts_val,
                )
            )
        else:
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="HSTS",
                    status="warn",
                    detail=f"HSTS max-age ({max_age}s) is shorter than the recommended 180 days (15552000s).",
                    value=hsts_val,
                )
            )
    else:
        if is_https:
            risk_pts = 10
            total_risk_points += risk_pts
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="HSTS",
                    status="fail",
                    detail="Strict-Transport-Security header is missing (SSL stripping vulnerability).",
                )
            )
            findings.append(
                ContentFindingSchema(
                    category="security_headers",
                    title="Missing HTTP Strict Transport Security (HSTS) Header",
                    severity="medium",
                    confidence=0.92,
                    description="The server does not publish an HSTS header. Browsers may allow unencrypted downgrade attacks (SSL stripping).",
                    evidence={"missing_header": "Strict-Transport-Security"},
                    recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    risk_points=risk_pts,
                )
            )

    # 3. Content-Security-Policy (CSP)
    csp_val = norm_headers.get("content-security-policy")
    csp_present = False

    if csp_val:
        csp_present = True
        csp_lower = csp_val.lower()
        if "unsafe-eval" in csp_lower or "unsafe-inline" in csp_lower:
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="Content Security Policy",
                    status="warn",
                    detail="CSP header is present but permits 'unsafe-inline' or 'unsafe-eval' script execution.",
                    value=csp_val[:80] + "...",
                )
            )
            findings.append(
                ContentFindingSchema(
                    category="security_headers",
                    title="Permissive Content Security Policy (CSP)",
                    severity="low",
                    confidence=0.85,
                    description="The CSP allows 'unsafe-inline' or 'unsafe-eval', reducing resilience against Cross-Site Scripting (XSS).",
                    evidence={"csp": csp_val[:120]},
                    recommendation="Remove 'unsafe-inline' and 'unsafe-eval' from script-src directives in favor of nonces or hashes.",
                    risk_points=5,
                )
            )
        else:
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="Content Security Policy",
                    status="pass",
                    detail="Content Security Policy is defined and restricts unauthorized script sources.",
                    value=csp_val[:80] + "...",
                )
            )
    else:
        risk_pts = 10
        total_risk_points += risk_pts
        headers_evaluated.append(
            SecurityHeaderItem(
                name="Content Security Policy",
                status="fail",
                detail="Content-Security-Policy header is missing (elevated XSS and injection risk).",
            )
        )
        findings.append(
            ContentFindingSchema(
                category="security_headers",
                title="Missing Content-Security-Policy (CSP) Header",
                severity="medium",
                confidence=0.90,
                description="No Content-Security-Policy header was detected. Malicious scripts can be executed and external assets loaded.",
                evidence={"missing_header": "Content-Security-Policy"},
                recommendation="Implement a robust CSP restricting script-src, object-src, and frame-ancestors.",
                risk_points=risk_pts,
            )
        )

    # 4. X-Frame-Options (Clickjacking)
    xfo_val = norm_headers.get("x-frame-options")
    xfo_present = False

    if xfo_val:
        xfo_present = True
        xfo_clean = xfo_val.lower()
        if xfo_clean in ("deny", "sameorigin"):
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="X-Frame-Options",
                    status="pass",
                    detail=f"X-Frame-Options set to '{xfo_val.upper()}' (prevents clickjacking framing).",
                    value=xfo_val,
                )
            )
        else:
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="X-Frame-Options",
                    status="warn",
                    detail=f"X-Frame-Options has unusual value: {xfo_val}",
                    value=xfo_val,
                )
            )
    else:
        risk_pts = 10
        total_risk_points += risk_pts
        headers_evaluated.append(
            SecurityHeaderItem(
                name="X-Frame-Options",
                status="fail",
                detail="X-Frame-Options header is missing (clickjacking / UI redressing risk).",
            )
        )
        findings.append(
            ContentFindingSchema(
                category="security_headers",
                title="Missing X-Frame-Options (Clickjacking Protection)",
                severity="medium",
                confidence=0.92,
                description="The page does not prevent framing in iframes. Attackers can embed this page in a transparent iframe to hijack clicks.",
                evidence={"missing_header": "X-Frame-Options"},
                recommendation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                risk_points=risk_pts,
            )
        )

    # 5. X-Content-Type-Options (MIME-Sniffing)
    xcto_val = norm_headers.get("x-content-type-options")
    xcto_present = False

    if xcto_val and xcto_val.lower() == "nosniff":
        xcto_present = True
        headers_evaluated.append(
            SecurityHeaderItem(
                name="X-Content-Type-Options",
                status="pass",
                detail="X-Content-Type-Options is correctly set to 'nosniff'.",
                value=xcto_val,
            )
        )
    else:
        risk_pts = 5
        total_risk_points += risk_pts
        headers_evaluated.append(
            SecurityHeaderItem(
                name="X-Content-Type-Options",
                status="fail",
                detail="X-Content-Type-Options header is missing (MIME sniffing attack risk).",
            )
        )
        findings.append(
            ContentFindingSchema(
                category="security_headers",
                title="Missing X-Content-Type-Options Header",
                severity="low",
                confidence=0.88,
                description="Without 'X-Content-Type-Options: nosniff', older browsers may treat user-uploaded files as executable script/HTML.",
                evidence={"missing_header": "X-Content-Type-Options"},
                recommendation="Add 'X-Content-Type-Options: nosniff'.",
                risk_points=risk_pts,
            )
        )

    # 6. Referrer-Policy
    ref_val = norm_headers.get("referrer-policy")
    ref_present = bool(ref_val)

    if ref_val:
        ref_lower = ref_val.lower()
        if "unsafe-url" in ref_lower:
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="Referrer Policy",
                    status="warn",
                    detail="Referrer-Policy is set to 'unsafe-url', which may leak full query strings and sensitive tokens.",
                    value=ref_val,
                )
            )
        else:
            headers_evaluated.append(
                SecurityHeaderItem(
                    name="Referrer Policy",
                    status="pass",
                    detail=f"Referrer-Policy is configured ({ref_val}).",
                    value=ref_val,
                )
            )
    else:
        headers_evaluated.append(
            SecurityHeaderItem(
                name="Referrer Policy",
                status="warn",
                detail="No Referrer-Policy specified. Browsers will use default fallback.",
            )
        )

    # 7. Permissions-Policy
    perm_val = norm_headers.get("permissions-policy") or norm_headers.get("feature-policy")
    perm_present = bool(perm_val)

    if perm_val:
        headers_evaluated.append(
            SecurityHeaderItem(
                name="Permissions Policy",
                status="pass",
                detail="Permissions-Policy restricts access to sensitive APIs (camera, microphone, geolocation).",
                value=perm_val[:60] + "...",
            )
        )
    else:
        headers_evaluated.append(
            SecurityHeaderItem(
                name="Permissions Policy",
                status="fail",
                detail="Permissions-Policy header is missing.",
            )
        )

    # 8. Server Software & Information Disclosure
    server_val = norm_headers.get("server")
    x_powered_by = norm_headers.get("x-powered-by")
    x_aspnet = norm_headers.get("x-aspnet-version")

    server_disclosure_str: Optional[str] = None
    if server_val:
        # Check if version numbers are included (e.g. Apache/2.4.41, nginx/1.18.0)
        if re.search(r"\d+\.\d+", server_val):
            tech_disclosures.append(f"Server: {server_val}")
            server_disclosure_str = server_val

    if x_powered_by:
        tech_disclosures.append(f"X-Powered-By: {x_powered_by}")
    if x_aspnet:
        tech_disclosures.append(f"X-AspNet-Version: {x_aspnet}")

    if tech_disclosures:
        findings.append(
            ContentFindingSchema(
                category="security_headers",
                title="Server Technology & Version Information Disclosure",
                severity="low",
                confidence=0.85,
                description=(
                    "The server discloses specific underlying software versions in HTTP response headers. "
                    "This assists automated vulnerability scanners in identifying unpatched CVEs."
                ),
                evidence={"disclosed_headers": tech_disclosures},
                recommendation="Disable banner tokens (e.g. ServerTokens Prod, expose_php = off).",
                risk_points=5,
            )
        )

    # 9. Cookie Security Evaluation
    if cookies_raw:
        for raw_c in cookies_raw:
            parts = [p.strip() for p in raw_c.split(";")]
            c_name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
            parts_lower = [p.lower() for p in parts]

            has_secure = "secure" in parts_lower
            has_httponly = "httponly" in parts_lower

            same_site_val = None
            for p in parts:
                if p.lower().startswith("samesite="):
                    same_site_val = p.split("=")[1].strip()
                    break

            is_safe = has_secure and has_httponly and same_site_val in ("Lax", "Strict", "lax", "strict")
            cookies_evaluated.append(
                CookieSecurityItem(
                    name=c_name,
                    has_secure=has_secure,
                    has_httponly=has_httponly,
                    same_site=same_site_val,
                    is_safe=is_safe,
                    detail=f"Secure: {has_secure}, HttpOnly: {has_httponly}, SameSite: {same_site_val or 'None'}",
                )
            )

            # Flag insecure cookies
            if not has_secure and is_https:
                findings.append(
                    ContentFindingSchema(
                        category="security_headers",
                        title=f"Cookie Missing 'Secure' Flag ({c_name})",
                        severity="medium",
                        confidence=0.90,
                        description=f"Cookie '{c_name}' does not have the 'Secure' attribute set. It can be transmitted in plain text.",
                        evidence={"cookie_name": c_name},
                        recommendation="Set the 'Secure' attribute on all session and tracking cookies.",
                        risk_points=10,
                    )
                )

            if not has_httponly:
                findings.append(
                    ContentFindingSchema(
                        category="security_headers",
                        title=f"Cookie Missing 'HttpOnly' Flag ({c_name})",
                        severity="low",
                        confidence=0.88,
                        description=f"Cookie '{c_name}' lacks the 'HttpOnly' flag, allowing JavaScript access via document.cookie (XSS token theft risk).",
                        evidence={"cookie_name": c_name},
                        recommendation="Set 'HttpOnly' flag on all sensitive authentication and session cookies.",
                        risk_points=5,
                    )
                )

    # 10. Security Grade Calculation (A+, A, B, C, D, F)
    pass_count = sum(1 for h in headers_evaluated if h.status == "pass")
    fail_count = sum(1 for h in headers_evaluated if h.status == "fail")

    if hsts_present and csp_present and xfo_present and xcto_present and not tech_disclosures:
        grade = "A+"
    elif hsts_present and (csp_present or xfo_present) and xcto_present:
        grade = "A"
    elif xfo_present and xcto_present:
        grade = "B"
    elif xfo_present or xcto_present:
        grade = "C"
    elif pass_count >= 1:
        grade = "D"
    else:
        grade = "F"

    # Overall Severity & Summary
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

    summary = (
        f"Web Security Grade: {grade}. Evaluated {len(headers_evaluated)} defensive headers with "
        f"{pass_count} passing and {fail_count} missing/failing."
    )

    return SecurityHeadersAnalysisResult(
        https_enforced=is_https,
        hsts_present=hsts_present,
        csp_present=csp_present,
        x_frame_options_present=xfo_present,
        x_content_type_options_present=xcto_present,
        referrer_policy_present=ref_present,
        permissions_policy_present=perm_present,
        security_grade=grade,
        headers_evaluated=headers_evaluated,
        cookies_evaluated=cookies_evaluated,
        server_disclosure=server_disclosure_str,
        technology_disclosures=tech_disclosures,
        findings=findings,
        total_risk_points=total_risk_points,
        max_severity=max_sev,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# PASSIVE NETWORK FETCHER & ANALYZER
# ---------------------------------------------------------------------------

async def fetch_and_analyze_security_headers(
    url: str,
    timeout: float = 3.0,
) -> SecurityHeadersAnalysisResult:
    """
    Passively fetches headers over HTTP/HTTPS and executes security checks.
    """
    is_https = url.lower().startswith("https://")
    headers: Dict[str, str] = {}
    cookies_raw: List[str] = []

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # Passive header collection even on self-signed certs
            headers={"User-Agent": SAFE_USER_AGENT},
        ) as client:
            resp = await client.head(url)
            # If HEAD returns 405 Method Not Allowed or 403, fallback to GET
            if resp.status_code in (403, 405, 501):
                resp = await client.get(url, headers={"Range": "bytes=0-1024"})

            headers = dict(resp.headers)
            # Extract raw Set-Cookie headers
            cookies_raw = resp.headers.get_list("set-cookie")
            is_https = str(resp.url).lower().startswith("https://")
    except Exception as e:
        # If network error occurs, return basic failure result
        pass

    return analyze_security_headers(
        headers=headers,
        target_url=url,
        cookies_raw=cookies_raw,
        is_https=is_https,
    )


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE FOR SECURITY HEADERS
# ---------------------------------------------------------------------------

def save_security_headers_findings_to_db_sync(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Session,
) -> List[ScanFinding]:
    """
    Synchronously persists security header findings into the `scan_findings` table.
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


async def save_security_headers_findings_to_db(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Any,
) -> List[ScanFinding]:
    """
    Asynchronously persists security header findings into the `scan_findings` table.
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
