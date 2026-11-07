"""
API endpoints for Domain Watchlist Management & Continuous Monitoring.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.core.exceptions import AppException
from app.models.watchlist import WatchlistItem
from app.models.alert import Alert
from app.models.user import User
from app.schemas.watchlist import (
    WatchlistCreate,
    WatchlistResponse,
    WatchlistListResponse,
)

router = APIRouter(prefix="/watchlist", tags=["Domain Watchlist"])


@router.post(
    "",
    response_model=WatchlistResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a domain to user's continuous monitoring watchlist",
)
async def add_to_watchlist(
    payload: WatchlistCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Subscribes a domain to security alert monitoring.
    """
    clean = payload.domain.strip().lower()
    if "://" in clean:
        clean = urlparse(clean).netloc.split(":")[0]
    domain = clean

    if not domain or "." not in domain:
        raise AppException(
            message="Invalid domain name format.",
            code="INVALID_DOMAIN",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Check if already in watchlist
    query = select(WatchlistItem).where(
        WatchlistItem.user_id == current_user.id,
        WatchlistItem.domain == domain,
    )
    res = await db.execute(query)
    existing = res.scalar_one_or_none()

    if existing:
        if not existing.is_active:
            existing.is_active = True
            existing.alert_types = payload.alert_types
            await db.commit()
            await db.refresh(existing)
            return existing
        raise AppException(
            message=f"Domain '{domain}' is already in your watchlist.",
            code="DOMAIN_ALREADY_WATCHED",
            status_code=status.HTTP_409_CONFLICT,
        )

    item = WatchlistItem(
        user_id=current_user.id,
        domain=domain,
        alert_types=payload.alert_types,
        last_checked_at=datetime.now(timezone.utc),
        is_active=True,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)

    # Generate initial monitoring welcome alert
    welcome_alert = Alert(
        user_id=current_user.id,
        watchlist_item_id=item.id,
        alert_type="monitoring_active",
        message=f"Continuous security monitoring initialized for {domain}.",
        is_read=False,
    )
    db.add(welcome_alert)
    await db.commit()

    return WatchlistResponse(
        id=item.id,
        user_id=item.user_id,
        domain=item.domain,
        alert_types=item.alert_types,
        last_checked_at=item.last_checked_at,
        last_risk_score=item.last_risk_score,
        last_verdict=item.last_verdict,
        cert_days_left=item.cert_days_left,
        is_active=item.is_active,
        created_at=item.created_at,
        unread_alerts_count=1,
    )


@router.get(
    "",
    response_model=WatchlistListResponse,
    summary="List all watched domains for the current user",
)
async def list_watchlist(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the user's active monitored domains.
    """
    query = (
        select(WatchlistItem)
        .where(
            WatchlistItem.user_id == current_user.id,
            WatchlistItem.is_active == True,
        )
        .order_by(desc(WatchlistItem.created_at))
    )
    res = await db.execute(query)
    items = res.scalars().all()

    # Get unread alerts count per item
    results: List[WatchlistResponse] = []
    for it in items:
        count_q = select(func.count(Alert.id)).where(
            Alert.watchlist_item_id == it.id,
            Alert.is_read == False,
        )
        count_res = await db.execute(count_q)
        unread = count_res.scalar() or 0

        results.append(
            WatchlistResponse(
                id=it.id,
                user_id=it.user_id,
                domain=it.domain,
                alert_types=it.alert_types,
                last_checked_at=it.last_checked_at,
                last_risk_score=it.last_risk_score,
                last_verdict=it.last_verdict,
                cert_days_left=it.cert_days_left,
                is_active=it.is_active,
                created_at=it.created_at,
                unread_alerts_count=unread,
            )
        )

    return WatchlistListResponse(
        total=len(results),
        items=results,
    )


@router.delete(
    "/{item_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a domain from the user's watchlist",
)
async def delete_from_watchlist(
    item_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Deactivates domain monitoring.
    """
    query = select(WatchlistItem).where(
        WatchlistItem.id == item_id,
        WatchlistItem.user_id == current_user.id,
    )
    res = await db.execute(query)
    item = res.scalar_one_or_none()

    if not item:
        raise AppException(
            message="Watchlist item not found.",
            code="WATCHLIST_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    item.is_active = False
    await db.commit()
    return None

