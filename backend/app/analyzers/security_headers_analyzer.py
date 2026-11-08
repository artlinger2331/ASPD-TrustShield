"""
TrustShield Web Security Headers & Passive Configuration Analyzer (Adapter)
Delegates to web_security_analyzer.py while maintaining full backwards compatibility.
"""

from typing import List, Dict, Any, Optional
import uuid
from sqlalchemy.orm import Session

from app.schemas.security_headers import (
    WebSecurityCheckItem,
    SecurityHeaderItem,
    CookieSecurityItem,
    SecurityHeadersAnalysisResult,
)
from app.models.scan_finding import ScanFinding
from app.schemas.content_analysis import ContentFindingSchema

from app.services.web_security_analyzer import (
    SAFE_USER_AGENT,
    SAFE_PROBE_PATHS,
    verify_env_content,
    verify_git_config_content,
    verify_zip_content,
    verify_admin_content,
    analyze_web_security,
    fetch_and_analyze_web_security,
    save_web_security_findings_to_db_sync,
    save_web_security_findings_to_db,
)


def analyze_security_headers(
    headers: Dict[str, str],
    target_url: str,
    cookies_raw: Optional[List[str]] = None,
    is_https: bool = True,
    html_content: Optional[str] = None,
    http_redirect_status: Optional[int] = None,
    http_redirect_target: Optional[str] = None,
    exposed_path_probes: Optional[Dict[str, Dict[str, Any]]] = None,
) -> SecurityHeadersAnalysisResult:
    """
    Backwards-compatible wrapper delegating to analyze_web_security.
    """
    return analyze_web_security(
        target_url=target_url,
        headers=headers,
        cookies_raw=cookies_raw,
        html_content=html_content,
        http_redirect_status=http_redirect_status,
        http_redirect_target=http_redirect_target,
        exposed_path_probes=exposed_path_probes,
        is_https=is_https,
    )


async def fetch_and_analyze_security_headers(
    url: str,
    timeout: float = 2.5,
    probe_exposed_paths: bool = True,
) -> SecurityHeadersAnalysisResult:
    """
    Backwards-compatible wrapper delegating to fetch_and_analyze_web_security.
    """
    return await fetch_and_analyze_web_security(
        url=url,
        timeout=timeout,
        probe_exposed_paths=probe_exposed_paths,
    )


def save_security_headers_findings_to_db_sync(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Session,
) -> List[ScanFinding]:
    """
    Backwards-compatible wrapper delegating to save_web_security_findings_to_db_sync.
    """
    return save_web_security_findings_to_db_sync(scan_id=scan_id, findings=findings, db=db)


async def save_security_headers_findings_to_db(
    scan_id: uuid.UUID,
    findings: List[ContentFindingSchema],
    db: Any,
) -> List[ScanFinding]:
    """
    Backwards-compatible wrapper delegating to save_web_security_findings_to_db.
    """
    return await save_web_security_findings_to_db(scan_id=scan_id, findings=findings, db=db)


__all__ = [
    "SAFE_USER_AGENT",
    "SAFE_PROBE_PATHS",
    "WebSecurityCheckItem",
    "SecurityHeaderItem",
    "CookieSecurityItem",
    "SecurityHeadersAnalysisResult",
    "verify_env_content",
    "verify_git_config_content",
    "verify_zip_content",
    "verify_admin_content",
    "analyze_web_security",
    "fetch_and_analyze_web_security",
    "save_web_security_findings_to_db_sync",
    "save_web_security_findings_to_db",
    "analyze_security_headers",
    "fetch_and_analyze_security_headers",
    "save_security_headers_findings_to_db_sync",
    "save_security_headers_findings_to_db",
]
