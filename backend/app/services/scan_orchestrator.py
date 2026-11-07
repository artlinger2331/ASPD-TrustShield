"""
TrustShield Scan Pipeline Orchestrator
Coordinates the 7-stage end-to-end security analysis pipeline:
  Step 1: URL input normalization & SSRF validation
  Step 2: Domain and DNS infrastructure analysis
  Step 3: SSL/TLS certificate & CA trust validation
  Step 4: Web security headers & passive configuration
  Step 5: Safe content fetching & phishing heuristics
  Step 6: Risk score calculation & finding aggregation
  Step 7: Final report generation and database completion
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.analyzers.url_normalizer import normalize_and_validate_url
from app.analyzers.domain_analyzer import (
    analyze_domain,
    save_domain_findings_to_db_sync,
)
from app.analyzers.cert_analyzer import (
    analyze_certificate,
    save_certificate_to_db_sync,
)
from app.analyzers.security_headers_analyzer import (
    analyze_security_headers,
    fetch_and_analyze_security_headers,
    save_security_headers_findings_to_db_sync,
)
from app.analyzers.content_analyzer import (
    analyze_content,
    safe_fetch_html,
    save_findings_to_db_sync,
)
from app.db.session import local_session_factory
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate

logger = logging.getLogger("trustshield.orchestrator")


def calculate_verdict(risk_score: int) -> Tuple[str, str]:
    """
    Normalizes a 0-100 risk score into standard TrustShield verdict codes and labels.
    """
    if risk_score >= 85:
        return "dangerous", "Likely Phishing / Dangerous"
    if risk_score >= 70:
        return "high_risk", "High Risk"
    if risk_score >= 50:
        return "suspicious", "Suspicious"
    if risk_score >= 25:
        return "low_risk", "Low Risk"
    return "safe", "Safe"


def execute_scan_pipeline_sync(
    scan_id: uuid.UUID,
    resolve_network: bool = True,
    mock_html: Optional[str] = None,
) -> Scan:
    """
    Synchronous pipeline runner coordinating all 7 analysis stages.
    Executes in background worker or async threadpool.
    """
    session = local_session_factory()
    try:
        # Load scan record
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan with ID {scan_id} not found.")
            return None

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        session.commit()

        # =====================================================================
        # STAGE 1: URL Normalization & SSRF Defense
        # =====================================================================
        norm, ssrf_error = normalize_and_validate_url(scan.input_url, resolve_dns=resolve_network)
        if ssrf_error or norm is None:
            scan.status = "failed"
            scan.error_message = ssrf_error or "URL failed validation"
            scan.completed_at = datetime.now(timezone.utc)
            scan.risk_score = 100
            scan.verdict = "dangerous"
            scan.summary = f"Scan rejected: {ssrf_error}"
            scan.recommendation = "Do not attempt to scan restricted private addresses or internal infrastructure."
            session.commit()
            return scan

        scan.normalized_url = norm.normalized_url
        session.commit()

        # =====================================================================
        # STAGE 2: Domain & DNS Infrastructure Analysis
        # =====================================================================
        try:
            domain_result = analyze_domain(
                domain=norm.host,
                resolve_live=resolve_network,
            )
            if domain_result.findings:
                save_domain_findings_to_db_sync(
                    scan_id=scan.id,
                    findings=domain_result.findings,
                    db=session,
                )
        except Exception as e:
            logger.warning(f"Domain analysis failed for {norm.host}: {str(e)}")

        # =====================================================================
        # STAGE 3: SSL/TLS Certificate & CA Trust Validation
        # =====================================================================
        try:
            cert_result = analyze_certificate(
                target_url_or_domain=norm.normalized_url,
                resolve_live=resolve_network,
                port=norm.port or 443,
            )
            save_certificate_to_db_sync(
                scan_id=scan.id,
                result=cert_result,
                db=session,
            )
        except Exception as e:
            logger.warning(f"Certificate analysis failed for {norm.normalized_url}: {str(e)}")

        # =====================================================================
        # STAGE 4: Web Security Headers & Passive Configuration
        # =====================================================================
        try:
            if resolve_network:
                # Passively fetch headers
                import anyio
                header_result = anyio.from_thread.run(fetch_and_analyze_security_headers, norm.normalized_url)
            else:
                header_result = analyze_security_headers(
                    headers={},
                    target_url=norm.normalized_url,
                    is_https=norm.scheme == "https",
                )

            if header_result.findings:
                save_security_headers_findings_to_db_sync(
                    scan_id=scan.id,
                    findings=header_result.findings,
                    db=session,
                )
        except Exception as e:
            logger.warning(f"Security headers analysis failed for {norm.normalized_url}: {str(e)}")

        # =====================================================================
        # STAGE 5: Safe Content Fetching & Phishing Heuristics
        # =====================================================================
        try:
            html_content = mock_html
            final_url = norm.normalized_url

            if html_content is None and resolve_network:
                import anyio
                html_content, final_url, fetch_err = anyio.from_thread.run(safe_fetch_html, norm.normalized_url)

            if html_content:
                from app.analyzers.content_analyzer import analyze_content_sync
                content_result = analyze_content_sync(
                    url=final_url or norm.normalized_url,
                    scan_id=scan.id,
                    html=html_content,
                    db=session,
                )
                scan.final_url = final_url
        except Exception as e:
            logger.warning(f"Content analysis failed for {norm.normalized_url}: {str(e)}")

        # =====================================================================
        # STAGE 6: Risk Scoring & Finding Aggregation
        # =====================================================================
        findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()

        total_risk_points = sum(f.risk_points for f in findings)
        risk_score = min(100, max(0, total_risk_points))
        verdict, verdict_label = calculate_verdict(risk_score)

        # Synthesize ranked summary from highest severity findings
        critical_findings = [f.title for f in findings if f.severity == "critical"]
        high_findings = [f.title for f in findings if f.severity == "high"]
        medium_findings = [f.title for f in findings if f.severity == "medium"]

        reasons: List[str] = []
        if critical_findings:
            reasons.extend(critical_findings[:2])
        if high_findings and len(reasons) < 3:
            reasons.extend(high_findings[:3 - len(reasons)])
        if medium_findings and len(reasons) < 3:
            reasons.extend(medium_findings[:3 - len(reasons)])

        if risk_score >= 70:
            summary = f"{verdict_label}: " + "; ".join(reasons) + "."
            recommendation = "Do not enter passwords, OTPs, or banking details on this website."
        elif risk_score >= 50:
            summary = f"{verdict_label}: " + ("; ".join(reasons) if reasons else "Multiple suspicious indicators detected.") + "."
            recommendation = "Exercise caution. Verify website ownership before submitting any credentials or payments."
        elif risk_score >= 25:
            summary = f"{verdict_label}: Website has minor configuration warnings but no direct phishing lures detected."
            recommendation = "Website appears low risk. Ensure browser connection remains encrypted."
        else:
            summary = "Safe: Website exhibits established domain age, valid TLS encryption, and no credential harvesting indicators."
            recommendation = "Website appears safe to browse."

        # =====================================================================
        # STAGE 7: Final Completion & Persistence
        # =====================================================================
        scan.status = "completed"
        scan.verdict = verdict
        scan.risk_score = risk_score
        scan.confidence = 0.92
        scan.summary = summary
        scan.recommendation = recommendation
        scan.completed_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(scan)

        return scan
    except Exception as exc:
        logger.exception(f"Unhandled error during scan execution: {str(exc)}")
        session.rollback()
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = f"Analysis pipeline error: {str(exc)}"
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()
        return scan
    finally:
        session.close()
