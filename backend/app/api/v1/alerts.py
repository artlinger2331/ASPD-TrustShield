"""
API endpoints for Security Alerts Management.
"""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.core.exceptions import AppException
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertResponse, AlertListResponse

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get(
    "",
    response_model=AlertListResponse,
    summary="Get user security alerts with unread counter",
)
async def get_user_alerts(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves user notification alerts regarding monitored domains.
    """
    unread_q = select(func.count(Alert.id)).where(
        Alert.user_id == current_user.id,
        Alert.is_read == False,
    )
    unread_res = await db.execute(unread_q)
    unread_count = unread_res.scalar() or 0

    total_q = select(func.count(Alert.id)).where(Alert.user_id == current_user.id)
    total_res = await db.execute(total_q)
    total = total_res.scalar() or 0

    query = (
        select(Alert)
        .where(Alert.user_id == current_user.id)
        .order_by(desc(Alert.created_at))
        .limit(limit)
        .offset(offset)
    )
    res = await db.execute(query)
    items = res.scalars().all()

    return AlertListResponse(
        unread_count=unread_count,
        total=total,
        items=[AlertResponse.model_validate(a) for a in items],
    )


@router.patch(
    "/{alert_id}/read",
    response_model=AlertResponse,
    summary="Mark a specific alert as read",
)
async def mark_alert_read(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Sets is_read = True on the specified alert.
    """
    query = select(Alert).where(
        Alert.id == alert_id,
        Alert.user_id == current_user.id,
    )
    res = await db.execute(query)
    alert = res.scalar_one_or_none()

    if not alert:
        raise AppException(
            message="Alert not found.",
            code="ALERT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    alert.is_read = True
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post(
    "/mark-all-read",
    summary="Mark all user alerts as read",
)
async def mark_all_alerts_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Sets is_read = True on all alerts for the current user.
    """
    stmt = (
        update(Alert)
        .where(Alert.user_id == current_user.id, Alert.is_read == False)
        .values(is_read=True)
    )
    await db.execute(stmt)
    await db.commit()
    return {"status": "success", "message": "All alerts marked as read."}
