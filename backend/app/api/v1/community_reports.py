"""
API endpoints for Community Threat Reporting and Voting.
"""

import uuid
from typing import Optional, List
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_optional_current_user
from app.core.exceptions import AppException
from app.models.community_report import CommunityReport
from app.models.user import User
from app.schemas.community_report import (
    CommunityReportCreate,
    CommunityReportVote,
    CommunityReportResponse,
    CommunityReportListResponse,
)

router = APIRouter(prefix="/community-reports", tags=["Community Threat Reports"])


@router.post(
    "",
    response_model=CommunityReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a community threat report for a malicious URL",
)
async def submit_community_report(
    payload: CommunityReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Submits a user or security researcher threat report.
    """
    url = payload.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0].lower()
    if not domain:
        raise AppException(
            message="Invalid target domain provided.",
            code="INVALID_DOMAIN",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    report = CommunityReport(
        url=url,
        domain=domain,
        reporter_id=current_user.id if current_user else None,
        threat_type=payload.threat_type,
        description=payload.description,
        screenshot_url=payload.screenshot_url,
        source="community",
        status="pending",
        confirmations=1,
        false_positive_votes=0,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return report


@router.get(
    "",
    response_model=CommunityReportListResponse,
    summary="List community threat reports with optional filtering",
)
async def list_community_reports(
    threat_type: Optional[str] = Query(None, description="Filter by threat category"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (pending, verified, rejected)"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves crowdsourced community reports.
    """
    query = select(CommunityReport)
    count_query = select(func.count(CommunityReport.id))

    if threat_type:
        query = query.where(CommunityReport.threat_type == threat_type)
        count_query = count_query.where(CommunityReport.threat_type == threat_type)
    if status_filter:
        query = query.where(CommunityReport.status == status_filter)
        count_query = count_query.where(CommunityReport.status == status_filter)
    if domain:
        query = query.where(CommunityReport.domain.ilike(f"%{domain}%"))
        count_query = count_query.where(CommunityReport.domain.ilike(f"%{domain}%"))

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(desc(CommunityReport.created_at)).limit(limit).offset(offset)
    result = await db.execute(query)
    items = result.scalars().all()

    return CommunityReportListResponse(
        total=total,
        items=[CommunityReportResponse.model_validate(r) for r in items],
    )


@router.post(
    "/{report_id}/vote",
    response_model=CommunityReportResponse,
    summary="Upvote (confirm) or downvote (false positive) a community threat report",
)
async def vote_on_community_report(
    report_id: uuid.UUID,
    payload: CommunityReportVote,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    """
    Records a community verification vote.
    """
    query = select(CommunityReport).where(CommunityReport.id == report_id)
    res = await db.execute(query)
    report = res.scalar_one_or_none()

    if not report:
        raise AppException(
            message="Community report not found.",
            code="REPORT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if payload.vote_type == "confirm":
        report.confirmations += 1
        if report.confirmations >= 3 and report.status == "pending":
            report.status = "verified"
    elif payload.vote_type == "false_positive":
        report.false_positive_votes += 1
        if report.false_positive_votes >= 5:
            report.status = "rejected"
    else:
        raise AppException(
            message="vote_type must be either 'confirm' or 'false_positive'.",
            code="INVALID_VOTE_TYPE",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    await db.commit()
    await db.refresh(report)
    return report
