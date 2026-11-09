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
from typing import Optional, List, Dict, Any, Tuple

from app.analyzers.url_normalizer import (
    normalize_and_validate_url,
    save_url_heuristic_findings_to_db_sync,
)
from app.analyzers.domain_analyzer import (
    analyze_domain,
    save_domain_findings_to_db_sync,
)
from app.analyzers.brand_impersonation import (
    analyze_brand_impersonation,
    save_brand_impersonation_findings_to_db_sync,
)
from app.analyzers.cert_analyzer import (
    analyze_certificate,
    save_certificate_to_db_sync,
)
from app.services.web_security_analyzer import (
    analyze_web_security,
    fetch_and_analyze_web_security,
    save_web_security_findings_to_db_sync,
)
from app.analyzers.content_analyzer import (
    analyze_content,
    analyze_content_sync,
    safe_fetch_html,
    save_findings_to_db_sync,
)
from app.analyzers.threat_intel_analyzer import (
    analyze_threat_intel,
    save_threat_intel_to_db_sync,
)
from app.analyzers.ml_classifier import (
    classify_url,
    save_ml_classification_to_db_sync,
)
from app.services.risk_engine import evaluate_risk
from app.core.config import settings
from app.db.session import local_session_factory
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.models.community_report import CommunityReport


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
) -> Optional[Scan]:
    """
    Synchronous pipeline runner coordinating all 6 analysis stages matching the frontend stepper.
    Commits findings incrementally, preserves partial findings on failure, and updates step/action.
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
        scan.current_step = 1
        scan.current_action = "Resolving DNS records, domain infrastructure & whois..."
        session.commit()

        # =====================================================================
        # STAGE 1: URL Normalization & SSRF Defense + DNS & Domain Infrastructure
        # =====================================================================
        norm, ssrf_error = normalize_and_validate_url(scan.input_url, resolve_dns=resolve_network)
        if ssrf_error or norm is None:
            scan.status = "failed"
            scan.error_message = ssrf_error or "URL failed validation"
            scan.completed_at = datetime.now(timezone.utc)
            scan.risk_score = 100
            scan.verdict = "dangerous"
            scan.current_step = 1
            scan.current_action = f"URL rejected: {ssrf_error}"
            scan.summary = f"Scan rejected: {ssrf_error}"
            scan.recommendation = "Do not attempt to scan restricted private addresses or internal infrastructure."
            session.commit()
            return scan

        scan.normalized_url = norm.normalized_url
        session.commit()

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
            logger.warning(f"Domain analysis failed for {norm.host}: {e}")
<<<<<<< HEAD

        # =====================================================================
        # ML URL Classification (After URL & Domain Analysis)
        # =====================================================================
        ml_result = None
        if getattr(settings, "ENABLE_ML_CLASSIFICATION", True):
            try:
                domain_context = {}
                if "domain_result" in locals() and domain_result:
                    if getattr(domain_result, "domain_age_days", None) is not None:
                        domain_context["domain_age_days"] = domain_result.domain_age_days
                    if getattr(domain_result, "dns_records", None):
                        domain_context["num_dns_records"] = len(domain_result.dns_records)
                    if getattr(domain_result, "has_mx", False):
                        domain_context["has_mx_records"] = 1
                    if getattr(domain_result, "has_txt", False):
                        domain_context["has_txt_records"] = 1
                    if getattr(domain_result, "min_ttl", None) is not None:
                        domain_context["ttl_value"] = domain_result.min_ttl

                ml_result = classify_url(norm.normalized_url, metadata=domain_context)
                if ml_result:
                    save_ml_classification_to_db_sync(
                        scan_id=scan.id,
                        result=ml_result,
                        db=session,
                    )
            except Exception as e:
                logger.warning(f"ML classification failed for {norm.normalized_url}: {e} (continuing scan)")

        # Transition to Step 2: SSL/TLS
        scan.current_step = 2
        scan.current_action = "Inspecting X.509 certificate chain, SAN domains & TLS cipher suites..."
        session.commit()

        # =====================================================================
=======

        # Transition to Step 2: SSL/TLS
        scan.current_step = 2
        scan.current_action = "Inspecting X.509 certificate chain, SAN domains & TLS cipher suites..."
        session.commit()

        # =====================================================================
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
        # STAGE 2: SSL/TLS Certificate & CA Trust Validation
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
            logger.warning(f"Certificate analysis failed for {norm.normalized_url}: {e}")

        # Transition to Step 3: Web Security Headers & Exposed Paths
        scan.current_step = 3
        scan.current_action = "Tracing redirects, security headers & exposed paths..."
        session.commit()

        # =====================================================================
        # STAGE 3: Web Security Headers & Exposed Paths
        # =====================================================================
        try:
            if resolve_network:
                import anyio
                web_sec_result = anyio.from_thread.run(fetch_and_analyze_web_security, norm.normalized_url)
            else:
                web_sec_result = analyze_web_security(
                    target_url=norm.normalized_url,
                    headers={},
                    is_https=norm.scheme == "https",
                )

            if web_sec_result.findings:
                save_web_security_findings_to_db_sync(
                    scan_id=scan.id,
                    findings=web_sec_result.findings,
                    db=session,
                )
        except Exception as e:
            logger.warning(f"Web security analysis failed for {norm.normalized_url}: {e}")

        # Transition to Step 4: DOM & Phishing Content
        scan.current_step = 4
        scan.current_action = "Safely parsing DOM, checking login forms, password inputs & scripts..."
        session.commit()

        # =====================================================================
        # STAGE 4: Safe Content Fetching & Phishing DOM Analysis
        # =====================================================================
        try:
            html_content = mock_html
            final_url = norm.normalized_url

            if html_content is None and resolve_network:
                import anyio
                html_content, final_url, fetch_err = anyio.from_thread.run(safe_fetch_html, norm.normalized_url)

            if html_content:
                content_result = analyze_content_sync(
                    url=final_url or norm.normalized_url,
                    scan_id=scan.id,
                    html=html_content,
                    db=session,
                )
                scan.final_url = final_url
                session.commit()
        except Exception as e:
            logger.warning(f"Content analysis failed for {norm.normalized_url}: {e}")

        # Transition to Step 5: Heuristics & Brand Impersonation
        scan.current_step = 5
        scan.current_action = "Executing homoglyph detection, brand impersonation & typosquatting..."
        session.commit()

        # =====================================================================
        # STAGE 5: Brand Impersonation & URL Heuristics
        # =====================================================================
        try:
            if getattr(norm, "heuristics", None) and norm.heuristics.findings_list:
                save_url_heuristic_findings_to_db_sync(
                    scan_id=scan.id,
                    findings=norm.heuristics.findings_list,
                    db=session,
                )

            brand_matches = analyze_brand_impersonation(norm.host)
            if brand_matches:
                save_brand_impersonation_findings_to_db_sync(
                    scan_id=scan.id,
                    matches=brand_matches,
                    db=session,
                )
        except Exception as e:
            logger.warning(f"Heuristics/Brand analysis failed for {norm.host}: {e}")

        # Transition to Step 6: Threat Intel Feeds
        scan.current_step = 6
        scan.current_action = "Cross-referencing threat intelligence feeds & IOCs..."
        session.commit()

        # =====================================================================
        # STAGE 6: Threat Intelligence Feeds
        # =====================================================================
        try:
            intel_result = analyze_threat_intel(
                url=norm.normalized_url,
                resolve_network=resolve_network,
            )
            save_threat_intel_to_db_sync(
                scan_id=scan.id,
                result=intel_result,
                db=session,
            )
        except Exception as e:
            logger.warning(f"Threat intelligence query failed for {norm.normalized_url}: {e}")

        # =====================================================================
        # STAGE 7: Explainable Risk Engine Synthesis & Report Finalization
        # =====================================================================
        scan.current_action = "Synthesizing risk score and final report..."
        session.commit()

        findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        cert = session.query(Certificate).filter(Certificate.scan_id == scan.id).first()
        threat_results = session.query(ThreatIntelResult).filter(ThreatIntelResult.scan_id == scan.id).all()

        # Query crowdsourced community threat reports for this domain / URL
        target_domain = getattr(norm, "base_domain", None) or getattr(norm, "host", None) or ""
        community_reports = (
            session.query(CommunityReport)
            .filter(
                (CommunityReport.domain == target_domain)
                | (CommunityReport.url == norm.normalized_url)
            )
            .all()
        )
        redirect_hops = getattr(norm, "redirect_chain", []) or []

        evaluation = evaluate_risk(
            findings=findings,
            certificate=cert,
            threat_intel_results=threat_results,
            ml_result=None,
            domain=norm.host,
            redirect_hops=redirect_hops,
            community_reports=community_reports,
        )

        scan.status = "completed"
        scan.verdict = evaluation.verdict
        scan.risk_score = evaluation.risk_score
        scan.confidence = evaluation.confidence
        scan.summary = evaluation.summary
        scan.recommendation = evaluation.recommendation
        scan.explanation = {
            "risk_score": evaluation.risk_score,
            "verdict": evaluation.verdict,
            "confidence": evaluation.confidence,
            "summary": evaluation.summary,
            "recommendation": evaluation.recommendation,
            "top_reasons": evaluation.top_reasons,
            "category_scores": evaluation.category_scores,
            "evidence": evaluation.evidence,
        }
        scan.completed_at = datetime.now(timezone.utc)
        scan.current_step = 6
        scan.current_action = "Scan completed successfully"
        session.commit()
        session.refresh(scan)

        return scan
    except Exception as exc:
        logger.exception(f"Unhandled error during scan execution: {str(exc)}")
        try:
            # Query whatever findings have already been persisted so they are preserved
            findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan_id).all()
            cert = session.query(Certificate).filter(Certificate.scan_id == scan_id).first()
            threat_results = session.query(ThreatIntelResult).filter(ThreatIntelResult.scan_id == scan_id).all()

            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = f"Analysis pipeline error: {str(exc)}"
                scan.completed_at = datetime.now(timezone.utc)
                scan.current_action = f"Scan failed: {str(exc)}"

                # Evaluate preliminary score from partial findings if available
                if findings or cert or threat_results:
                    try:
                        evaluation = evaluate_risk(
                            findings=findings,
                            certificate=cert,
                            threat_intel_results=threat_results,
                            ml_result=None,
                            domain=getattr(scan, "normalized_url", None) or "unknown",
                        )
                        scan.verdict = evaluation.verdict
                        scan.risk_score = evaluation.risk_score
                        scan.confidence = evaluation.confidence
                        scan.summary = f"Partial scan completed with error: {str(exc)}"
                        scan.recommendation = evaluation.recommendation
<<<<<<< HEAD
                        scan.explanation = {
                            "risk_score": evaluation.risk_score,
                            "verdict": evaluation.verdict,
                            "confidence": evaluation.confidence,
                            "summary": scan.summary,
                            "recommendation": evaluation.recommendation,
                            "top_reasons": evaluation.top_reasons,
                            "category_scores": evaluation.category_scores,
                            "evidence": evaluation.evidence,
                        }
=======
>>>>>>> 9b735eb99fcfab11611f7f8da03c77f43357eb91
                    except Exception as eval_err:
                        logger.warning(f"Preliminary risk evaluation failed: {eval_err}")

                session.commit()
                return scan
        except Exception as recovery_exc:
            logger.exception(f"Failed to record scan failure state: {recovery_exc}")
            session.rollback()
        return None
    finally:
        session.close()
