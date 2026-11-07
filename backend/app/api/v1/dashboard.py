"""
Dashboard API endpoints for SecOps Telemetry, Threat Metrics & Historical Trends.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.watchlist import WatchlistItem
from app.schemas.dashboard import DashboardStatsResponse, ThreatDistribution, DailyTrendPoint

router = APIRouter(prefix="/dashboard", tags=["Dashboard Telemetry"])


@router.get(
    "/stats",
    response_model=DashboardStatsResponse,
    summary="Retrieve aggregated SecOps telemetry metrics and trend history",
    status_code=status.HTTP_200_OK,
)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
) -> DashboardStatsResponse:
    """
    Computes live dashboard statistics: total scans, threat verdicts distribution,
    clean percentage, category breakdowns, and 7-day trend telemetry.
    """
    # 1. Total Scans Count
    total_q = select(func.count(Scan.id))
    total_res = await db.execute(total_q)
    total_scans = total_res.scalar() or 0

    # 2. Verdict Counts
    malicious_q = select(func.count(Scan.id)).where(Scan.verdict == "dangerous")
    malicious_res = await db.execute(malicious_q)
    malicious_count = malicious_res.scalar() or 0

    suspicious_q = select(func.count(Scan.id)).where(Scan.verdict == "suspicious")
    suspicious_res = await db.execute(suspicious_q)
    suspicious_count = suspicious_res.scalar() or 0

    safe_q = select(func.count(Scan.id)).where(Scan.verdict == "safe")
    safe_res = await db.execute(safe_q)
    safe_count = safe_res.scalar() or 0

    clean_pct = round((safe_count / total_scans * 100), 1) if total_scans > 0 else 100.0

    # 3. Average Risk Score
    avg_score_q = select(func.avg(Scan.risk_score))
    avg_score_res = await db.execute(avg_score_q)
    avg_score_val = avg_score_res.scalar()
    avg_score = round(float(avg_score_val), 1) if avg_score_val is not None else 18.5

    # 4. Active Watchlist Count
    watchlist_q = select(func.count(WatchlistItem.id)).where(WatchlistItem.is_active == True)
    watchlist_res = await db.execute(watchlist_q)
    active_monitors = watchlist_res.scalar() or 0

    # 5. Threat Distribution Categories
    finding_cat_q = select(
        ScanFinding.category,
        func.count(ScanFinding.id),
    ).group_by(ScanFinding.category)
    finding_cat_res = await db.execute(finding_cat_q)
    cat_counts = dict(finding_cat_res.all())

    distribution = ThreatDistribution(
        phishing=cat_counts.get("credential_harvesting", 0) + cat_counts.get("phishing", 0) + cat_counts.get("login_form", 0),
        malware=cat_counts.get("suspicious_scripts", 0) + cat_counts.get("clickfix_deception", 0),
        scam=cat_counts.get("brand_impersonation", 0) + cat_counts.get("deceptive_content", 0),
        suspicious_certs=cat_counts.get("tls_certificate", 0) + cat_counts.get("weak_cryptography", 0),
        header_vulnerabilities=cat_counts.get("security_headers", 0),
    )

    # 6. 7-Day Chart Trends Telemetry (Single batch query aggregated in memory)
    now = datetime.now(timezone.utc)
    seven_days_ago = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)

    recent_q = select(Scan.created_at, Scan.verdict, Scan.risk_score).where(
        Scan.created_at >= seven_days_ago
    )
    recent_res = await db.execute(recent_q)
    recent_records = recent_res.all()

    # Bucket records by date string
    buckets: Dict[str, Dict[str, Any]] = {}
    for i in range(6, -1, -1):
        d_str = (now - timedelta(days=i)).strftime("%b %d")
        buckets[d_str] = {"scans": 0, "threats": 0, "scores": []}

    for rec in recent_records:
        rec_time = rec[0]
        if rec_time:
            # Ensure timezone-aware comparison if needed
            rec_date_str = rec_time.strftime("%b %d")
            if rec_date_str in buckets:
                buckets[rec_date_str]["scans"] += 1
                if rec[1] in ("dangerous", "suspicious"):
                    buckets[rec_date_str]["threats"] += 1
                if rec[2] is not None:
                    buckets[rec_date_str]["scores"].append(rec[2])

    trends: List[DailyTrendPoint] = []
    for d_str, b_data in buckets.items():
        avg_score_day = (
            round(sum(b_data["scores"]) / len(b_data["scores"]), 1)
            if b_data["scores"]
            else 0.0
        )
        trends.append(
            DailyTrendPoint(
                date=d_str,
                scans=b_data["scans"],
                threats=b_data["threats"],
                avg_score=avg_score_day,
            )
        )

    return DashboardStatsResponse(
        total_scans=total_scans,
        malicious_detected=malicious_count,
        suspicious_detected=suspicious_count,
        safe_detected=safe_count,
        clean_percentage=clean_pct,
        avg_risk_score=avg_score,
        active_monitors_count=active_monitors,
        threat_distribution=distribution,
        chart_trends=trends,
    )
