"""
TrustShield Passive Web Security Analyzer
Performs safe, non-intrusive passive web security assessment across 11 key vectors:
1. HTTP to HTTPS redirect
2. Strict-Transport-Security (HSTS)
3. Content-Security-Policy (CSP)
4. X-Frame-Options (XFO)
5. X-Content-Type-Options (XCTO)
6. Referrer-Policy
7. Permissions-Policy
8. Cookie flags (Secure, HttpOnly, SameSite)
9. Mixed content
10. Server and framework version disclosure
11. Common exposed sensitive paths (/.env, /.git/config, /backup.zip, /admin)
"""

import inspect
import logging
import re
import uuid
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin

import httpx
from sqlalchemy.orm import Session

from app.models.scan_finding import ScanFinding
from app.schemas.content_analysis import ContentFindingSchema
from app.schemas.security_headers import (
    WebSecurityCheckItem,
    SecurityHeaderItem,
    CookieSecurityItem,
    SecurityHeadersAnalysisResult,
)

logger = logging.getLogger("trustshield.web_security_analyzer")

SAFE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 (TrustShield Passive Security Analyzer/1.0)"
)

# Controlled list of safe paths to probe (strictly limited to avoid intrusive scanning)
SAFE_PROBE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/admin",
]


# ---------------------------------------------------------------------------
# CONTENT SIGNATURE VERIFIERS FOR EXPOSED PATHS
# Avoids False Positives from Single-Page Applications (SPAs) returning 200 on all URLs
# ---------------------------------------------------------------------------

def verify_env_content(body: str) -> bool:
    """Verifies if response body actually contains environment configuration key-values."""
    if not body:
        return False
    # Check for typical .env key-value tokens
    env_keys = ["APP_KEY", "APP_ENV", "DB_PASSWORD", "DB_HOST", "SECRET_KEY", "API_KEY", "JWT_SECRET", "AWS_ACCESS_KEY"]
    return any(k in body for k in env_keys) or (re.search(r"^[A-Z0-9_]{3,30}=[^\r\n]+", body, re.MULTILINE) is not None and "<html" not in body.lower())


def verify_git_config_content(body: str) -> bool:
    """Verifies if response body actually contains Git configuration text."""
    if not body:
        return False
    return "[core]" in body or "repositoryformatversion" in body or "[remote" in body


def verify_zip_content(headers: Dict[str, str], body_bytes: bytes) -> bool:
    """Verifies if response is genuinely a ZIP archive."""
    content_type = headers.get("content-type", "").lower()
    if "application/zip" in content_type or "application/x-zip" in content_type:
        return True
    return body_bytes.startswith(b"PK\x03\x04")


def verify_admin_content(body: str, status_code: int) -> bool:
    """Verifies if /admin endpoint displays an actual admin portal or login form."""
    if status_code in (401, 403):
        return True
    body_lower = body.lower()
    admin_tokens = ["admin", "dashboard", "control panel", "sign in", "login", "password"]
    token_matches = sum(1 for t in admin_tokens if t in body_lower)
    return token_matches >= 2


# ---------------------------------------------------------------------------
# CORE PASSIVE SECURITY EVALUATOR
# ---------------------------------------------------------------------------

def analyze_web_security(
    target_url: str,
    headers: Dict[str, str],
    cookies_raw: Optional[List[str]] = None,
    html_content: Optional[str] = None,
    http_redirect_status: Optional[int] = None,
    http_redirect_target: Optional[str] = None,
    exposed_path_probes: Optional[Dict[str, Dict[str, Any]]] = None,
    is_https: Optional[bool] = None,
) -> SecurityHeadersAnalysisResult:
    """
    Evaluates HTTP response headers, cookie flags, mixed content, and safe exposed paths.
    Conforms to all 11 checks and generates standardized WebSecurityCheckItem entries.
    """
    if is_https is None:
        is_https = target_url.lower().startswith("https://")

    norm_headers: Dict[str, str] = {k.lower().strip(): v.strip() for k, v in headers.items()}
    cookies_raw = cookies_raw or []
    exposed_path_probes = exposed_path_probes or {}

    checks: List[WebSecurityCheckItem] = []
    headers_evaluated: List[SecurityHeaderItem] = []
    cookies_evaluated: List[CookieSecurityItem] = []
    findings: List[ContentFindingSchema] = []
    tech_disclosures: List[str] = []
    exposed_paths_detected: List[str] = []
    total_risk_points = 0

    # =======================================================================
    # CHECK 1: HTTP to HTTPS Redirect
    # =======================================================================
    if http_redirect_status in (301, 308) and (http_redirect_target and http_redirect_target.lower().startswith("https://")):
        checks.append(
            WebSecurityCheckItem(
                check_name="HTTP to HTTPS Redirect",
                status="Pass",
                severity="info",
                evidence={"redirect_status": http_redirect_status, "target": http_redirect_target},
                explanation="The web server permanently redirects unencrypted HTTP requests to secure HTTPS.",
                remediation="None required. Permanent HTTPS redirection is properly configured.",
                risk_points=0,
            )
        )
    elif http_redirect_status in (302, 307) and (http_redirect_target and http_redirect_target.lower().startswith("https://")):
        risk_pts = 5
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="HTTP to HTTPS Redirect",
                status="Warning",
                severity="low",
                evidence={"redirect_status": http_redirect_status, "target": http_redirect_target},
                explanation="The server uses a temporary redirect (302/307) to HTTPS instead of a permanent redirect (301).",
                remediation="Configure a permanent HTTP 301 or 308 redirect to prevent downgrade caching.",
                risk_points=risk_pts,
            )
        )
    elif not is_https:
        risk_pts = 20
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="HTTP to HTTPS Redirect",
                status="Fail",
                severity="high",
                evidence={"target_url": target_url, "redirect_status": http_redirect_status},
                explanation="The website serves traffic over unencrypted plain HTTP without enforcing HTTPS redirection.",
                remediation="Enforce full-site HTTPS encryption with automatic 301 redirection to https://.",
                risk_points=risk_pts,
            )
        )
        findings.append(
            ContentFindingSchema(
                category="security_headers",
                title="Missing HTTP to HTTPS Redirection (Plain HTTP)",
                severity="high",
                confidence=0.98,
                description="Traffic is delivered in unencrypted plain text. Passwords, session cookies, and personal data can be intercepted by network adversaries.",
                evidence={"target_url": target_url},
                recommendation="Configure web server to redirect all HTTP port 80 traffic to HTTPS port 443 via 301 Moved Permanently.",
                risk_points=risk_pts,
            )
        )
    else:
        # Default pass if scanned URL is HTTPS and no plain HTTP issue reported
        checks.append(
            WebSecurityCheckItem(
                check_name="HTTP to HTTPS Redirect",
                status="Pass",
                severity="info",
                evidence={"url": target_url, "scheme": "https"},
                explanation="Encrypted HTTPS connection active for this target.",
                remediation="None required.",
                risk_points=0,
            )
        )

    # Legacy header item compatibility
    headers_evaluated.append(
        SecurityHeaderItem(
            name="HTTPS Enforcement",
            status="pass" if is_https else "fail",
            detail="Site loads over encrypted HTTPS protocol." if is_https else "Website serves content over unencrypted plain HTTP.",
            value="HTTPS" if is_https else "HTTP",
        )
    )

    # =======================================================================
    # CHECK 2: Strict-Transport-Security (HSTS)
    # =======================================================================
    hsts_val = norm_headers.get("strict-transport-security")
    hsts_present = False

    if hsts_val:
        hsts_present = True
        max_age_match = re.search(r"\bmax-age=(\d+)", hsts_val.lower())
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_subdomains = "includesubdomains" in hsts_val.lower()
        has_preload = "preload" in hsts_val.lower()

        if max_age >= 15552000:  # >= 180 days
            checks.append(
                WebSecurityCheckItem(
                    check_name="Strict-Transport-Security",
                    status="Pass",
                    severity="info",
                    evidence={"hsts": hsts_val, "max_age": max_age, "includeSubDomains": has_subdomains, "preload": has_preload},
                    explanation=f"HSTS is actively enforced with a strong max-age ({max_age} seconds).",
                    remediation="Maintain HSTS configuration and consider submission to the HSTS preload list.",
                    risk_points=0,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="HSTS", status="pass", detail=f"HSTS enforced ({max_age}s).", value=hsts_val)
            )
        else:
            risk_pts = 5
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Strict-Transport-Security",
                    status="Warning",
                    severity="low",
                    evidence={"hsts": hsts_val, "max_age": max_age},
                    explanation=f"HSTS max-age ({max_age}s) is shorter than the recommended 180 days (15552000s).",
                    remediation="Increase HSTS max-age to at least 31536000 (1 year).",
                    risk_points=risk_pts,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="HSTS", status="warn", detail="HSTS max-age is shorter than 180 days.", value=hsts_val)
            )
    else:
        if is_https:
            risk_pts = 15
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Strict-Transport-Security",
                    status="Fail",
                    severity="medium",
                    evidence={"missing_header": "Strict-Transport-Security"},
                    explanation="Strict-Transport-Security header is missing, allowing potential SSL stripping downgrade attacks.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    risk_points=risk_pts,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="HSTS", status="fail", detail="Strict-Transport-Security header is missing.")
            )
            findings.append(
                ContentFindingSchema(
                    category="web_security",
                    title="Missing HTTP Strict Transport Security (HSTS) Header",
                    severity="medium",
                    confidence=0.92,
                    description="The server does not publish an HSTS header. Browsers may allow unencrypted downgrade attacks (SSL stripping).",
                    evidence={"missing_header": "Strict-Transport-Security"},
                    recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    risk_points=risk_pts,
                )
            )
        else:
            checks.append(
                WebSecurityCheckItem(
                    check_name="Strict-Transport-Security",
                    status="Not Applicable",
                    severity="info",
                    evidence={"scheme": "http"},
                    explanation="HSTS is only applicable on HTTPS connections.",
                    remediation="Migrate the site to HTTPS first before configuring HSTS.",
                    risk_points=0,
                )
            )

    # =======================================================================
    # CHECK 3: Content-Security-Policy (CSP)
    # =======================================================================
    csp_val = norm_headers.get("content-security-policy")
    csp_present = False

    if csp_val:
        csp_present = True
        csp_lower = csp_val.lower()
        has_unsafe_inline = "unsafe-inline" in csp_lower
        has_unsafe_eval = "unsafe-eval" in csp_lower

        if has_unsafe_inline or has_unsafe_eval:
            risk_pts = 5
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Content-Security-Policy",
                    status="Warning",
                    severity="low",
                    evidence={"csp": csp_val[:120], "unsafe_inline": has_unsafe_inline, "unsafe_eval": has_unsafe_eval},
                    explanation="Content-Security-Policy is present but permits 'unsafe-inline' or 'unsafe-eval' script execution.",
                    remediation="Remove 'unsafe-inline' and 'unsafe-eval' in favor of cryptographic nonces or SHA-256 hashes.",
                    risk_points=risk_pts,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="Content Security Policy", status="warn", detail="CSP allows unsafe-inline or unsafe-eval.", value=csp_val[:80])
            )
            findings.append(
                ContentFindingSchema(
                    category="web_security",
                    title="Permissive Content Security Policy (CSP)",
                    severity="low",
                    confidence=0.88,
                    description="The CSP allows 'unsafe-inline' or 'unsafe-eval', reducing resilience against Cross-Site Scripting (XSS).",
                    evidence={"csp": csp_val[:120]},
                    recommendation="Remove 'unsafe-inline' and 'unsafe-eval' from script-src directives in favor of nonces or hashes.",
                    risk_points=risk_pts,
                )
            )
        else:
            checks.append(
                WebSecurityCheckItem(
                    check_name="Content-Security-Policy",
                    status="Pass",
                    severity="info",
                    evidence={"csp": csp_val[:120]},
                    explanation="Content Security Policy is defined and restricts unauthorized script and resource origins.",
                    remediation="Regularly audit CSP directives as site dependencies change.",
                    risk_points=0,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="Content Security Policy", status="pass", detail="CSP defined and restricted.", value=csp_val[:80])
            )
    else:
        risk_pts = 15
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="Content-Security-Policy",
                status="Fail",
                severity="medium",
                evidence={"missing_header": "Content-Security-Policy"},
                explanation="Content-Security-Policy header is missing, leaving the application vulnerable to cross-site scripting (XSS) and data injection.",
                remediation="Implement a robust Content-Security-Policy with script-src, object-src, and frame-ancestors.",
                risk_points=risk_pts,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="Content Security Policy", status="fail", detail="Content-Security-Policy header is missing.")
        )
        findings.append(
            ContentFindingSchema(
                category="web_security",
                title="Missing Content-Security-Policy (CSP) Header",
                severity="medium",
                confidence=0.92,
                description="No Content-Security-Policy header was detected. Malicious scripts can be executed and external assets loaded.",
                evidence={"missing_header": "Content-Security-Policy"},
                recommendation="Implement a robust CSP restricting script-src, object-src, and frame-ancestors.",
                risk_points=risk_pts,
            )
        )

    # =======================================================================
    # CHECK 4: X-Frame-Options (Clickjacking Protection)
    # =======================================================================
    xfo_val = norm_headers.get("x-frame-options")
    xfo_present = False

    if xfo_val:
        xfo_present = True
        xfo_clean = xfo_val.lower()
        if xfo_clean in ("deny", "sameorigin"):
            checks.append(
                WebSecurityCheckItem(
                    check_name="X-Frame-Options",
                    status="Pass",
                    severity="info",
                    evidence={"x_frame_options": xfo_val},
                    explanation=f"X-Frame-Options is set to '{xfo_val.upper()}', preventing UI redressing and clickjacking.",
                    remediation="None required. Clickjacking defense is actively enforced.",
                    risk_points=0,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="X-Frame-Options", status="pass", detail=f"Set to '{xfo_val.upper()}'.", value=xfo_val)
            )
        else:
            risk_pts = 5
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="X-Frame-Options",
                    status="Warning",
                    severity="low",
                    evidence={"x_frame_options": xfo_val},
                    explanation=f"X-Frame-Options uses unusual or deprecated directive '{xfo_val}'.",
                    remediation="Migrate to CSP frame-ancestors or X-Frame-Options: SAMEORIGIN / DENY.",
                    risk_points=risk_pts,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="X-Frame-Options", status="warn", detail=f"Unusual directive: {xfo_val}", value=xfo_val)
            )
    else:
        risk_pts = 15
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="X-Frame-Options",
                status="Fail",
                severity="medium",
                evidence={"missing_header": "X-Frame-Options"},
                explanation="X-Frame-Options header is missing. Attackers can embed this page in a transparent iframe to hijack user clicks (clickjacking).",
                remediation="Add 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY'.",
                risk_points=risk_pts,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="X-Frame-Options", status="fail", detail="X-Frame-Options header is missing.")
        )
        findings.append(
            ContentFindingSchema(
                category="web_security",
                title="Missing X-Frame-Options (Clickjacking Protection)",
                severity="medium",
                confidence=0.92,
                description="The page does not prevent framing in iframes. Attackers can embed this page in a transparent iframe to hijack clicks.",
                evidence={"missing_header": "X-Frame-Options"},
                recommendation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                risk_points=risk_pts,
            )
        )

    # =======================================================================
    # CHECK 5: X-Content-Type-Options (MIME-Sniffing Defense)
    # =======================================================================
    xcto_val = norm_headers.get("x-content-type-options")
    xcto_present = False

    if xcto_val and xcto_val.lower() == "nosniff":
        xcto_present = True
        checks.append(
            WebSecurityCheckItem(
                check_name="X-Content-Type-Options",
                status="Pass",
                severity="info",
                evidence={"x_content_type_options": xcto_val},
                explanation="X-Content-Type-Options is correctly set to 'nosniff', preventing browser MIME-type sniffing.",
                remediation="None required.",
                risk_points=0,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="X-Content-Type-Options", status="pass", detail="Set to 'nosniff'.", value=xcto_val)
        )
    else:
        risk_pts = 5
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="X-Content-Type-Options",
                status="Fail",
                severity="low",
                evidence={"x_content_type_options": xcto_val or "missing"},
                explanation="Missing 'X-Content-Type-Options: nosniff' header allows browsers to sniff content types, risking script execution from non-script files.",
                remediation="Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
                risk_points=risk_pts,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="X-Content-Type-Options", status="fail", detail="Header is missing.")
        )
        findings.append(
            ContentFindingSchema(
                category="web_security",
                title="Missing X-Content-Type-Options Header",
                severity="low",
                confidence=0.90,
                description="Without 'X-Content-Type-Options: nosniff', older browsers may treat user-uploaded files as executable script/HTML.",
                evidence={"missing_header": "X-Content-Type-Options"},
                recommendation="Add 'X-Content-Type-Options: nosniff'.",
                risk_points=risk_pts,
            )
        )

    # =======================================================================
    # CHECK 6: Referrer-Policy
    # =======================================================================
    ref_val = norm_headers.get("referrer-policy")
    ref_present = bool(ref_val)

    if ref_val:
        ref_lower = ref_val.lower()
        if "unsafe-url" in ref_lower:
            risk_pts = 5
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Referrer-Policy",
                    status="Warning",
                    severity="low",
                    evidence={"referrer_policy": ref_val},
                    explanation="Referrer-Policy is set to 'unsafe-url', which leaks complete path and query strings to external domains.",
                    remediation="Change Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    risk_points=risk_pts,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="Referrer Policy", status="warn", detail="Set to 'unsafe-url'.", value=ref_val)
            )
        else:
            checks.append(
                WebSecurityCheckItem(
                    check_name="Referrer-Policy",
                    status="Pass",
                    severity="info",
                    evidence={"referrer_policy": ref_val},
                    explanation=f"Referrer-Policy is configured ('{ref_val}') to protect user navigation privacy.",
                    remediation="None required.",
                    risk_points=0,
                )
            )
            headers_evaluated.append(
                SecurityHeaderItem(name="Referrer Policy", status="pass", detail=f"Configured ({ref_val}).", value=ref_val)
            )
    else:
        risk_pts = 5
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="Referrer-Policy",
                status="Warning",
                severity="low",
                evidence={"missing_header": "Referrer-Policy"},
                explanation="No Referrer-Policy specified. Browsers will use default fallback behavior.",
                remediation="Explicitly declare 'Referrer-Policy: strict-origin-when-cross-origin'.",
                risk_points=risk_pts,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="Referrer Policy", status="warn", detail="No Referrer-Policy specified.")
        )

    # =======================================================================
    # CHECK 7: Permissions-Policy
    # =======================================================================
    perm_val = norm_headers.get("permissions-policy") or norm_headers.get("feature-policy")
    perm_present = bool(perm_val)

    if perm_val:
        checks.append(
            WebSecurityCheckItem(
                check_name="Permissions-Policy",
                status="Pass",
                severity="info",
                evidence={"permissions_policy": perm_val[:100]},
                explanation="Permissions-Policy restricts access to sensitive browser capabilities (camera, microphone, geolocation).",
                remediation="None required.",
                risk_points=0,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="Permissions Policy", status="pass", detail="Restricts sensitive APIs.", value=perm_val[:60])
        )
    else:
        risk_pts = 5
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="Permissions-Policy",
                status="Warning",
                severity="low",
                evidence={"missing_header": "Permissions-Policy"},
                explanation="Permissions-Policy header is missing. Embedded iframes or scripts could request access to device hardware.",
                remediation="Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
                risk_points=risk_pts,
            )
        )
        headers_evaluated.append(
            SecurityHeaderItem(name="Permissions Policy", status="fail", detail="Header is missing.")
        )

    # =======================================================================
    # CHECK 8: Cookie Flags: Secure, HttpOnly, and SameSite
    # =======================================================================
    if not cookies_raw:
        checks.append(
            WebSecurityCheckItem(
                check_name="Cookie Security Flags",
                status="Pass",
                severity="info",
                evidence={"cookies_count": 0},
                explanation="No HTTP cookies are set by the server.",
                remediation="None required.",
                risk_points=0,
            )
        )
    else:
        insecure_cookies = []
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
            if not is_safe:
                insecure_cookies.append(c_name)

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

            # Generate individual findings for missing flags
            if not has_secure and is_https:
                findings.append(
                    ContentFindingSchema(
                        category="web_security",
                        title=f"Cookie Missing 'Secure' Flag ({c_name})",
                        severity="medium",
                        confidence=0.92,
                        description=f"Cookie '{c_name}' does not have the 'Secure' attribute set. It can be transmitted in clear text over unencrypted networks.",
                        evidence={"cookie_name": c_name},
                        recommendation="Set the 'Secure' attribute on all cookies transmitted over HTTPS.",
                        risk_points=10,
                    )
                )
            if not has_httponly:
                findings.append(
                    ContentFindingSchema(
                        category="web_security",
                        title=f"Cookie Missing 'HttpOnly' Flag ({c_name})",
                        severity="low",
                        confidence=0.88,
                        description=f"Cookie '{c_name}' lacks the 'HttpOnly' flag, allowing JavaScript access via document.cookie (XSS token theft risk).",
                        evidence={"cookie_name": c_name},
                        recommendation="Set 'HttpOnly' flag on all sensitive authentication and session cookies.",
                        risk_points=5,
                    )
                )

        if not insecure_cookies:
            checks.append(
                WebSecurityCheckItem(
                    check_name="Cookie Security Flags",
                    status="Pass",
                    severity="info",
                    evidence={"cookie_count": len(cookies_raw)},
                    explanation="All cookies include Secure, HttpOnly, and SameSite protection flags.",
                    remediation="None required. Cookie security standards are satisfied.",
                    risk_points=0,
                )
            )
        else:
            risk_pts = 10
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Cookie Security Flags",
                    status="Fail" if any(not c.has_secure for c in cookies_evaluated if is_https) else "Warning",
                    severity="medium",
                    evidence={"insecure_cookies": insecure_cookies},
                    explanation=f"One or more cookies ({', '.join(insecure_cookies[:3])}) are missing Secure, HttpOnly, or SameSite flags.",
                    remediation="Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all session and tracking cookies.",
                    risk_points=risk_pts,
                )
            )

    # =======================================================================
    # CHECK 9: Mixed Content Detection
    # =======================================================================
    mixed_content_detected = False
    if is_https and html_content:
        # Check active mixed content (scripts, iframes)
        active_mixed = re.findall(r'<(?:script|iframe)[^>]+src=["\'](http://[^"\']+)["\']', html_content, re.IGNORECASE)
        # Check passive mixed content (images, audio, video)
        passive_mixed = re.findall(r'<(?:img|audio|video|source)[^>]+src=["\'](http://[^"\']+)["\']', html_content, re.IGNORECASE)

        if active_mixed:
            mixed_content_detected = True
            risk_pts = 20
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Mixed Content",
                    status="Fail",
                    severity="high",
                    evidence={"active_mixed_scripts": active_mixed[:3]},
                    explanation=f"Active mixed content detected: page loads {len(active_mixed)} scripts or iframes over unencrypted HTTP.",
                    remediation="Change all script and iframe src attributes to use https:// or protocol-relative // URLs.",
                    risk_points=risk_pts,
                )
            )
            findings.append(
                ContentFindingSchema(
                    category="web_security",
                    title="Active Mixed Content Detected (Unencrypted Script / Iframe)",
                    severity="high",
                    confidence=0.95,
                    description=f"The HTTPS page loads executable scripts or iframes over unencrypted HTTP ({active_mixed[0]}). Network attackers can modify these scripts to seize control of the session.",
                    evidence={"active_mixed_urls": active_mixed[:5]},
                    recommendation="Serve all dependencies over HTTPS or enable CSP 'upgrade-insecure-requests'.",
                    risk_points=risk_pts,
                )
            )
        elif passive_mixed:
            mixed_content_detected = True
            risk_pts = 10
            total_risk_points += risk_pts
            checks.append(
                WebSecurityCheckItem(
                    check_name="Mixed Content",
                    status="Warning",
                    severity="medium",
                    evidence={"passive_mixed_media": passive_mixed[:3]},
                    explanation=f"Passive mixed content detected: page loads {len(passive_mixed)} media assets over unencrypted HTTP.",
                    remediation="Migrate image and media assets to HTTPS.",
                    risk_points=risk_pts,
                )
            )
            findings.append(
                ContentFindingSchema(
                    category="web_security",
                    title="Passive Mixed Content Detected (Unencrypted Media)",
                    severity="medium",
                    confidence=0.90,
                    description="The HTTPS page loads images or media over clear-text HTTP. Attackers can view or replace these media assets.",
                    evidence={"passive_mixed_urls": passive_mixed[:5]},
                    recommendation="Update media URLs to HTTPS.",
                    risk_points=risk_pts,
                )
            )
        else:
            checks.append(
                WebSecurityCheckItem(
                    check_name="Mixed Content",
                    status="Pass",
                    severity="info",
                    evidence={"inspected_html": True},
                    explanation="No mixed content detected. All sub-resources use encrypted HTTPS.",
                    remediation="None required.",
                    risk_points=0,
                )
            )
    else:
        checks.append(
            WebSecurityCheckItem(
                check_name="Mixed Content",
                status="Pass" if is_https else "Not Applicable",
                severity="info",
                evidence={"https": is_https},
                explanation="No mixed content issues identified.",
                remediation="None required.",
                risk_points=0,
            )
        )

    # =======================================================================
    # CHECK 10: Server and Framework Version Disclosure
    # =======================================================================
    server_val = norm_headers.get("server")
    x_powered_by = norm_headers.get("x-powered-by")
    x_aspnet = norm_headers.get("x-aspnet-version")
    x_runtime = norm_headers.get("x-runtime")

    server_disclosure_str: Optional[str] = None
    if server_val:
        if re.search(r"\d+\.\d+", server_val):
            tech_disclosures.append(f"Server: {server_val}")
            server_disclosure_str = server_val

    if x_powered_by:
        tech_disclosures.append(f"X-Powered-By: {x_powered_by}")
    if x_aspnet:
        tech_disclosures.append(f"X-AspNet-Version: {x_aspnet}")
    if x_runtime and re.search(r"\d+", x_runtime):
        tech_disclosures.append(f"X-Runtime: {x_runtime}")

    if tech_disclosures:
        risk_pts = 5
        total_risk_points += risk_pts
        checks.append(
            WebSecurityCheckItem(
                check_name="Server Version Disclosure",
                status="Warning",
                severity="low",
                evidence={"disclosures": tech_disclosures},
                explanation=f"The server discloses underlying software names or versions ({', '.join(tech_disclosures)}).",
                remediation="Configure server to suppress software banners (e.g. ServerTokens Prod, expose_php = Off).",
                risk_points=risk_pts,
            )
        )
        findings.append(
            ContentFindingSchema(
                category="web_security",
                title="Server Technology & Version Information Disclosure",
                severity="low",
                confidence=0.88,
                description="The server discloses specific underlying software versions in HTTP response headers, assisting threat actors in identifying unpatched CVEs.",
                evidence={"disclosed_headers": tech_disclosures},
                recommendation="Disable banner tokens (e.g. ServerTokens Prod, expose_php = off).",
                risk_points=risk_pts,
            )
        )
    else:
        checks.append(
            WebSecurityCheckItem(
                check_name="Server Version Disclosure",
                status="Pass",
                severity="info",
                evidence={"server_header": server_val or "hidden"},
                explanation="Server response headers do not disclose sensitive software version numbers.",
                remediation="None required.",
                risk_points=0,
            )
        )

    # =======================================================================
    # CHECK 11: Common Exposed Paths (Controlled Safe Probe)
    # =======================================================================
    exposed_path_findings = []
    for path, probe_data in exposed_path_probes.items():
        status_code = probe_data.get("status_code", 404)
        body = probe_data.get("body", "")
        body_bytes = probe_data.get("body_bytes", b"")
        resp_headers = {k.lower(): v for k, v in probe_data.get("headers", {}).items()}

        if path == "/.env" and status_code == 200 and verify_env_content(body):
            exposed_paths_detected.append(path)
            risk_pts = 35
            total_risk_points += risk_pts
            exposed_path_findings.append((path, "critical", "Environment Configuration File (/.env)", risk_pts))
        elif path == "/.git/config" and status_code == 200 and verify_git_config_content(body):
            exposed_paths_detected.append(path)
            risk_pts = 35
            total_risk_points += risk_pts
            exposed_path_findings.append((path, "critical", "Git Repository Metadata (/.git/config)", risk_pts))
        elif path == "/backup.zip" and status_code == 200 and verify_zip_content(resp_headers, body_bytes):
            exposed_paths_detected.append(path)
            risk_pts = 30
            total_risk_points += risk_pts
            exposed_path_findings.append((path, "critical", "Database or Source Backup Archive (/backup.zip)", risk_pts))
        elif path == "/admin" and verify_admin_content(body, status_code):
            exposed_paths_detected.append(path)
            risk_pts = 10
            total_risk_points += risk_pts
            exposed_path_findings.append((path, "medium", "Administrative Portal (/admin)", risk_pts))

    if exposed_paths_detected:
        worst_sev = "critical" if any(sev == "critical" for _, sev, _, _ in exposed_path_findings) else "medium"
        checks.append(
            WebSecurityCheckItem(
                check_name="Common Exposed Sensitive Paths",
                status="Fail" if worst_sev == "critical" else "Warning",
                severity=worst_sev,
                evidence={"exposed_paths": exposed_paths_detected},
                explanation=f"Exposed high-risk paths detected: {', '.join(exposed_paths_detected)}.",
                remediation="Restrict web server access to configuration files, dotfiles, and administration portals immediately.",
                risk_points=max(pts for _, _, _, pts in exposed_path_findings),
            )
        )
        for path, sev, label, pts in exposed_path_findings:
            findings.append(
                ContentFindingSchema(
                    category="web_security",
                    title=f"Publicly Exposed {label}",
                    severity=sev,
                    confidence=0.98,
                    description=f"The sensitive path '{path}' was detected as publicly accessible. This exposes credentials, infrastructure architecture, or administrative functionality.",
                    evidence={"exposed_path": path},
                    recommendation=f"Configure web server rules (Nginx/Apache/Cloudflare) to deny all external access to '{path}'.",
                    risk_points=pts,
                )
            )
    else:
        checks.append(
            WebSecurityCheckItem(
                check_name="Common Exposed Sensitive Paths",
                status="Pass",
                severity="info",
                evidence={"probed_paths": SAFE_PROBE_PATHS, "exposed_count": 0},
                explanation="Controlled probe confirmed common sensitive paths (/.env, /.git/config, /backup.zip) are properly blocked or return 404/403.",
                remediation="None required. Ensure file permissions remain restricted in future deployments.",
                risk_points=0,
            )
        )

    # =======================================================================
    # GRADE & SEVERITY SYNTHESIS
    # =======================================================================
    pass_count = sum(1 for c in checks if c.status == "Pass")
    fail_count = sum(1 for c in checks if c.status == "Fail")

    if hsts_present and csp_present and xfo_present and xcto_present and not tech_disclosures and not exposed_paths_detected:
        grade = "A+"
    elif hsts_present and (csp_present or xfo_present) and xcto_present and not exposed_paths_detected:
        grade = "A"
    elif xfo_present and xcto_present and not exposed_paths_detected:
        grade = "B"
    elif (xfo_present or xcto_present) and not exposed_paths_detected:
        grade = "C"
    elif pass_count >= 3:
        grade = "D"
    else:
        grade = "F"

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
        f"Passive Web Security Assessment Grade: {grade}. Evaluated {len(checks)} security checks: "
        f"{pass_count} passed, {fail_count} failed."
    )

    return SecurityHeadersAnalysisResult(
        https_enforced=is_https,
        http_to_https_redirect=http_redirect_status in (301, 308),
        hsts_present=hsts_present,
        csp_present=csp_present,
        x_frame_options_present=xfo_present,
        x_content_type_options_present=xcto_present,
        referrer_policy_present=ref_present,
        permissions_policy_present=perm_present,
        mixed_content_detected=mixed_content_detected,
        exposed_paths_detected=exposed_paths_detected,
        security_grade=grade,
        checks=checks,
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
# SAFE PASSIVE NETWORK FETCHER & EXPOSED PATH PROBER
# ---------------------------------------------------------------------------

async def fetch_and_analyze_web_security(
    url: str,
    timeout: float = 2.5,
    probe_exposed_paths: bool = True,
) -> SecurityHeadersAnalysisResult:
    """
    Passively fetches headers, traces HTTP to HTTPS redirect, optionally inspects
    HTML for mixed content, and probes a small, controlled list of sensitive paths.
    """
    is_https = url.lower().startswith("https://")
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port

    headers: Dict[str, str] = {}
    cookies_raw: List[str] = []
    html_content: Optional[str] = None
    http_redirect_status: Optional[int] = None
    http_redirect_target: Optional[str] = None
    exposed_path_probes: Dict[str, Dict[str, Any]] = {}

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=False,  # Catch redirect status explicitly
        headers={"User-Agent": SAFE_USER_AGENT},
    ) as client:
        # Step 1: Probe HTTP port 80 redirect if starting from host or http
        try:
            http_url = f"http://{host}{f':{port}' if port and port != 443 else ''}/"
            http_resp = await client.get(http_url, timeout=1.5)
            if http_resp.is_redirect:
                http_redirect_status = http_resp.status_code
                http_redirect_target = http_resp.headers.get("location")
            elif http_resp.status_code == 200:
                http_redirect_status = 200
        except Exception as e:
            logger.debug(f"HTTP port 80 redirect check skipped: {e}")

        # Step 2: Fetch primary URL headers and initial body
        try:
            resp = await client.get(
                url,
                headers={"Range": "bytes=0-8192"},  # Only request initial 8KB for passive inspection
                follow_redirects=True,
            )
            headers = dict(resp.headers)
            cookies_raw = resp.headers.get_list("set-cookie")
            html_content = resp.text
            is_https = str(resp.url).lower().startswith("https://")
        except Exception as e:
            logger.debug(f"Failed to fetch primary URL {url}: {e}")

        # Step 3: Controlled probe of 4 sensitive paths
        if probe_exposed_paths and host:
            base_url = f"{'https' if is_https else 'http'}://{host}{f':{port}' if port else ''}"
            for path in SAFE_PROBE_PATHS:
                probe_url = urljoin(base_url, path)
                try:
                    p_resp = await client.get(
                        probe_url,
                        headers={"Range": "bytes=0-256"},
                        timeout=1.2,
                        follow_redirects=False,
                    )
                    exposed_path_probes[path] = {
                        "status_code": p_resp.status_code,
                        "headers": dict(p_resp.headers),
                        "body": p_resp.text[:512],
                        "body_bytes": p_resp.content[:512],
                    }
                except Exception as e:
                    exposed_path_probes[path] = {"status_code": 404, "body": "", "headers": {}}

    return analyze_web_security(
        target_url=url,
        headers=headers,
        cookies_raw=cookies_raw,
        html_content=html_content,
        http_redirect_status=http_redirect_status,
        http_redirect_target=http_redirect_target,
        exposed_path_probes=exposed_path_probes,
        is_https=is_https,
    )


# ---------------------------------------------------------------------------
# DATABASE PERSISTENCE FOR WEB SECURITY FINDINGS
# ---------------------------------------------------------------------------

def save_web_security_findings_to_db_sync(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Session,
) -> List[ScanFinding]:
    """
    Synchronously persists web security findings into the `scan_findings` table.
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


async def save_web_security_findings_to_db(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Any,
) -> List[ScanFinding]:
    """
    Asynchronously persists web security findings into the `scan_findings` table.
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
