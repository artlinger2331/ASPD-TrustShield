"""
TrustShield Scans API Router.
Handles scan submission, status polling, telemetry reporting, and pre-flight URL validation.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, status, BackgroundTasks, Query
from sqlalchemy import select, desc, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_optional_current_user
from app.analyzers.url_normalizer import normalize_and_validate_url
from app.core.exceptions import AppException
from app.db.session import get_db, local_session_factory
from app.models.user import User
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanStatusResponse,
    ScanFindingResponse,
    CertificateReportResponse,
    ThreatIntelReportResponse,
    MLClassificationResponse,
    ScanReportResponse,
    ScanListItem,
    ScanListResponse,
)
from app.schemas.url_analysis import (
    URLValidationRequest,
    URLValidationResponse,
    URLParts,
    URLHeuristics,
    RedirectHop,
)
from app.services.scan_orchestrator import (
    execute_scan_pipeline_sync,
    calculate_verdict,
)
from app.tasks.scan_tasks import dispatch_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "/validate",
    response_model=URLValidationResponse,
    summary="Pre-flight URL validation, normalization, and heuristic threat check",
)
async def validate_url_endpoint(
    payload: URLValidationRequest,
):
    """
    Performs fast, production-grade URL validation, normalization, SSRF checking,
    and heuristic threat analysis without creating a full asynchronous database scan.
    Useful for the browser extension, UI pre-validation, and instant security verdicts.
    """
    norm, err = normalize_and_validate_url(payload.url, resolve_dns=payload.resolve_dns)
    if err or norm is None:
        return URLValidationResponse(
            is_valid=False,
            input_url=payload.url,
            normalized_url=None,
            error_message=err or "Invalid URL structure",
            parts=None,
            heuristics=None,
            redirect_chain=[],
            findings=[],
        )

    redirect_chain = []
    if payload.trace_redirects:
        from app.analyzers.url_normalizer import trace_redirects_safely_async
        _, hops, _ = await trace_redirects_safely_async(norm.normalized_url)
        redirect_chain = [
            RedirectHop(
                hop_number=h.hop_number,
                from_url=h.from_url,
                to_url=h.to_url,
                status_code=h.status_code,
                latency_ms=h.latency_ms,
            )
            for h in hops
        ]

    parts = URLParts(
        scheme=norm.scheme,
        host=norm.host,
        port=norm.port,
        registered_domain=norm.base_domain,
        subdomain=norm.subdomain,
        tld=norm.tld,
        path=norm.path,
        query=norm.query,
        query_params=norm.query_params,
        fragment=norm.fragment,
        unicode_host=norm.unicode_host,
    )

    heuristics = URLHeuristics(
        is_ip=norm.heuristics.is_ip,
        is_shortener=norm.heuristics.is_shortener,
        is_punycode=norm.heuristics.is_punycode,
        has_homoglyphs=norm.heuristics.has_homoglyphs,
        has_excessive_subdomains=norm.heuristics.has_excessive_subdomains,
        subdomain_count=norm.heuristics.subdomain_count,
        has_suspicious_tld=norm.heuristics.has_suspicious_tld,
        has_embedded_credentials=norm.heuristics.has_embedded_credentials,
        is_overly_long=norm.heuristics.is_overly_long,
        url_length=norm.heuristics.url_length,
        suspicious_keywords_found=norm.heuristics.suspicious_keywords_found,
        heuristic_risk_score=norm.heuristics.heuristic_risk_score,
    )

    return URLValidationResponse(
        is_valid=True,
        input_url=payload.url,
        normalized_url=norm.normalized_url,
        error_message=None,
        parts=parts,
        heuristics=heuristics,
        redirect_chain=redirect_chain,
        findings=norm.heuristics.findings_list,
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create and initiate a new website security scan",
)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submits a target URL for automated multi-vector security analysis.
    Validates input URL, performs initial SSRF pre-check, enqueues pipeline execution,
    and returns immediate scan token for stepper polling.
    """
    # 1. Validate & Normalize URL syntax
    norm, err = normalize_and_validate_url(payload.url, resolve_dns=False)
    if err or norm is None:
        raise AppException(
            message=err or "Invalid URL provided for scanning",
            code="INVALID_URL",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # 2. Check for active concurrent scan for the same normalized URL (last 5 minutes)
    five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    clean_target = norm.normalized_url.rstrip("/")
    existing_scan_stmt = (
        select(Scan)
        .where(
            or_(
                Scan.normalized_url == norm.normalized_url,
                Scan.normalized_url == clean_target,
                Scan.normalized_url == f"{clean_target}/",
            ),
            Scan.status.in_(["queued", "running"]),
            Scan.created_at >= five_minutes_ago,
        )
        .order_by(desc(Scan.created_at))
    )
    existing_res = await db.execute(existing_scan_stmt)
    existing_scan = existing_res.scalars().first()
    if existing_scan:
        return ScanResponse(
            id=existing_scan.id,
            input_url=existing_scan.input_url,
            normalized_url=existing_scan.normalized_url,
            status=existing_scan.status,
            current_step=existing_scan.current_step or 0,
            current_action=existing_scan.current_action,
            created_at=existing_scan.created_at,
        )

    # 3. Persist new Scan in queued status
    scan_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=scan_id,
        user_id=current_user.id if current_user else None,
        input_url=payload.url.strip(),
        normalized_url=norm.normalized_url,
        status="queued",
        current_step=0,
        current_action="Scan queued in worker pool",
        created_at=now,
        updated_at=now,
    )
    db.add(scan)
    await db.commit()

    # 4. Enqueue background execution via Celery or in-process fallback
    dispatch_scan(scan_id=scan.id, background_tasks=background_tasks)

    return ScanResponse(
        id=scan.id,
        input_url=scan.input_url,
        normalized_url=scan.normalized_url,
        status="queued",
        current_step=scan.current_step,
        current_action=scan.current_action,
        created_at=scan.created_at,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Poll real-time scan pipeline status and progress",
)
async def get_scan_status(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Lightweight endpoint polled by the frontend progressive stepper during scan execution.
    Returns status ('queued', 'running', 'completed', 'failed'), current active pipeline step (0-6),
    and interim risk score if completed.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise AppException(
            message=f"Scan record with ID '{scan_id}' was not found.",
            code="SCAN_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if scan.current_step is not None and scan.current_step > 0:
        current_step = scan.current_step
    else:
        step_map = {
            "queued": 0,
            "running": 1,
            "completed": 6,
            "failed": 0,
        }
        current_step = step_map.get(scan.status, 0)

    confidence = None
    if scan.confidence is not None:
        confidence = float(scan.confidence)

    return ScanStatusResponse(
        id=scan.id,
        status=scan.status,
        step=current_step,
        total_steps=6,
        current_action=scan.current_action,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        confidence=confidence,
        summary=scan.summary,
        recommendation=scan.recommendation,
        error_message=scan.error_message,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Retrieve comprehensive consolidated security report dossier",
)
async def get_scan_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns the complete structured dossier:
    - Input & normalized URLs, final verdict, risk score, confidence
    - Domain DNS architecture & registrar details
    - SSL/TLS certificate chain & security headers
    - Granular security findings list
    - Threat intelligence match results
    """
    query = (
        select(Scan)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.certificate),
            selectinload(Scan.threat_intel_results),
        )
        .where(Scan.id == scan_id)
    )

    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise AppException(
            message=f"Scan report with ID '{scan_id}' was not found.",
            code="SCAN_REPORT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Format Certificate details if available
    cert_response: Optional[CertificateReportResponse] = None
    if scan.certificate:
        c = scan.certificate
        cert_response = CertificateReportResponse(
            subject=c.subject,
            issuer=c.issuer,
            valid_from=c.valid_from,
            valid_to=c.valid_to,
            days_until_expiry=c.days_until_expiry,
            is_valid=c.is_valid,
            is_revoked=c.is_revoked,
            chain_valid=c.chain_valid,
            ct_log_present=c.ct_log_present,
            ca_trust_status=c.ca_trust_status,
            raw_certificate=c.raw_certificate or {},
        )

    # Format Findings list
    findings_response = [
        ScanFindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            category=f.category,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            evidence=f.evidence or {},
            recommendation=f.recommendation,
            risk_points=f.risk_points,
            created_at=f.created_at,
        )
        for f in (scan.findings or [])
    ]

    # Format Threat Intel results list
    threat_intel_response = [
        ThreatIntelReportResponse(
            source=t.source,
            match_type=t.match_type,
            details=t.details or {},
            confidence=t.confidence,
        )
        for t in (scan.threat_intel_results or [])
    ]

    # Format ML Classification response if present in findings
    ml_response: Optional[MLClassificationResponse] = None
    ml_finding = next((f for f in (scan.findings or []) if f.category == "ml_classifier"), None)
    if ml_finding and ml_finding.evidence:
        ev = ml_finding.evidence
        ml_response = MLClassificationResponse(
            url=scan.normalized_url or scan.input_url,
            predicted_label=ev.get("predicted_label", "phishing" if ev.get("phishing_probability", 0) >= 0.5 else "benign"),
            is_phishing=bool(ev.get("predicted_label") == "phishing" or ev.get("phishing_probability", 0) >= 0.5),
            phishing_probability=float(ev.get("phishing_probability", 0.0)),
            risk_score=int(ev.get("risk_score", ml_finding.risk_points or 0)),
            confidence=float(ev.get("confidence", ml_finding.confidence or 0.8)),
            verdict=ev.get("verdict", "safe"),
            model_version=ev.get("model_version", "v1.0.0"),
            top_contributing_features=ev.get("top_indicators", []),
            summary=ml_finding.description or "",
        )

    _, verdict_label = calculate_verdict(scan.risk_score or 0)
    confidence = float(scan.confidence) if scan.confidence is not None else None

    return ScanReportResponse(
        id=scan.id,
        input_url=scan.input_url,
        normalized_url=scan.normalized_url,
        final_url=scan.final_url,
        status=scan.status,
        verdict=scan.verdict,
        verdict_label=verdict_label,
        risk_score=scan.risk_score,
        confidence=confidence,
        summary=scan.summary,
        recommendation=scan.recommendation,
        dns_records=getattr(scan, "dns_records", None),
        security_headers=getattr(scan, "security_headers", None),
        findings=findings_response,
        certificate=cert_response,
        threat_intel=threat_intel_response,
        ml_result=ml_response,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
    )


@router.get(
    "",
    response_model=ScanListResponse,
    summary="List recent scans with envelope",
)
async def list_recent_scans(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns recent scans ordered by creation time descending with total count envelope.
    If authenticated, prioritizes the user's scan history; otherwise returns public recent scans.
    """
    count_q = select(func.count(Scan.id))
    query = select(Scan).order_by(desc(Scan.created_at)).limit(limit).offset(offset)
    if current_user:
        count_q = count_q.where(Scan.user_id == current_user.id)
        query = query.where(Scan.user_id == current_user.id)

    count_res = await db.execute(count_q)
    total_count = count_res.scalar() or 0

    result = await db.execute(query)
    scans = result.scalars().all()

    items = [
        ScanListItem(
            id=s.id,
            input_url=s.input_url,
            normalized_url=s.normalized_url,
            status=s.status,
            verdict=s.verdict,
            risk_score=s.risk_score,
            created_at=s.created_at,
        )
        for s in scans
    ]

    return ScanListResponse(
        total=total_count,
        items=items,
    )
