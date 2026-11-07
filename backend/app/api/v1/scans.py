"""
FastAPI router for Website Security Scans, Telemetry Polling, and Reports.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, BackgroundTasks, status, Query, Request
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

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
    ScanReportResponse,
    ScanListItem,
)
from app.services.scan_orchestrator import (
    execute_scan_pipeline_sync,
    calculate_verdict,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


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

    # 2. Persist new Scan in queued status
    scan_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=scan_id,
        user_id=current_user.id if current_user else None,
        input_url=payload.url.strip(),
        normalized_url=norm.normalized_url,
        status="queued",
        created_at=now,
        updated_at=now,
    )
    db.add(scan)
    await db.commit()

    # 3. Enqueue background execution
    background_tasks.add_task(execute_scan_pipeline_sync, scan_id=scan.id)

    return ScanResponse(
        id=scan.id,
        input_url=scan.input_url,
        normalized_url=scan.normalized_url,
        status="queued",
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
    Polls the active execution status of a scan for frontend progress steppers.
    """
    query = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(query)
    scan = result.scalar_one_or_none()

    if not scan:
        raise AppException(
            message="Scan not found",
            code="SCAN_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Determine dynamic stepper stage
    step = 0
    current_action = "Queued for security analysis"
    if scan.status == "running":
        # Check how many findings or sub-records exist to gauge step progress
        f_query = select(ScanFinding.category).where(ScanFinding.scan_id == scan.id)
        f_res = await db.execute(f_query)
        categories = set(f_res.scalars().all())

        if "security_headers" in categories or "credential_harvesting" in categories:
            step = 5
            current_action = "Analyzing page content, credential forms & brand signatures..."
        elif "tls_certificate" in categories:
            step = 4
            current_action = "Evaluating HTTP defense headers (HSTS, CSP, X-Frame-Options)..."
        elif "domain_infrastructure" in categories or "dns_security" in categories:
            step = 3
            current_action = "Performing passive TLS handshake and CA certificate trust verification..."
        else:
            step = 2
            current_action = "Inspecting domain age, DNS architecture, SPF & DMARC..."
    elif scan.status == "completed":
        step = 7
        current_action = "Analysis complete. Report generated."
    elif scan.status in ("failed", "timeout"):
        step = 7
        current_action = scan.error_message or "Scan execution failed"

    return ScanStatusResponse(
        id=scan.id,
        status=scan.status,
        step=step,
        total_steps=7,
        current_action=current_action,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        summary=scan.summary,
        recommendation=scan.recommendation,
        error_message=scan.error_message,
    )


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Retrieve complete security telemetry report and findings",
)
async def get_scan_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns full telemetry including all granular findings, SSL certificate details,
    threat intelligence feed matches, and security headers.
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
            message="Scan report not found",
            code="SCAN_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Compute duration
    duration = None
    if scan.started_at and scan.completed_at:
        duration = round((scan.completed_at - scan.started_at).total_seconds(), 2)

    verdict_code, verdict_label = calculate_verdict(scan.risk_score or 0)

    # Format findings
    findings_resp: List[ScanFindingResponse] = [
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

    # Format certificate
    cert_resp = None
    if scan.certificate:
        c = scan.certificate
        cert_resp = CertificateReportResponse(
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

    # Format threat intel
    threat_resp = [
        ThreatIntelReportResponse(
            source=t.source,
            match_type=t.match_type,
            confidence=t.confidence,
            details=t.details or {},
        )
        for t in (scan.threat_intel_results or [])
    ]

    return ScanReportResponse(
        id=scan.id,
        input_url=scan.input_url,
        normalized_url=scan.normalized_url,
        final_url=scan.final_url,
        status=scan.status,
        verdict=scan.verdict,
        verdict_label=verdict_label,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        summary=scan.summary,
        recommendation=scan.recommendation,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=duration,
        error_message=scan.error_message,
        findings=findings_resp,
        certificate=cert_resp,
        threat_intel=threat_resp,
    )


@router.get(
    "",
    response_model=List[ScanListItem],
    summary="List recent scan records for dashboard or user history",
)
async def list_recent_scans(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns recent scans ordered by creation time descending.
    If authenticated, prioritizes the user's scan history; otherwise returns public recent scans.
    """
    query = select(Scan).order_by(desc(Scan.created_at)).limit(limit).offset(offset)
    if current_user:
        query = query.where(Scan.user_id == current_user.id)

    result = await db.execute(query)
    scans = result.scalars().all()

    return [
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

