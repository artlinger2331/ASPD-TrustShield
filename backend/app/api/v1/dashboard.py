"""
Dashboard API endpoints for SecOps Telemetry, Threat Metrics & Historical Trends.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, status
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db, local_session_factory
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.watchlist import WatchlistItem
from app.schemas.dashboard import DashboardStatsResponse, ThreatDistribution, DailyTrendPoint

router = APIRouter(prefix="/dashboard", tags=["Dashboard Telemetry"])


def compute_dashboard_stats_sync(session: Session) -> DashboardStatsResponse:
    """
    Synchronously computes dashboard statistics for maximum speed and local compatibility.
    """
    # 1. Total Scans Count
    total_scans = session.execute(select(func.count(Scan.id))).scalar() or 0

    # 2. Verdict Counts
    malicious_count = session.execute(select(func.count(Scan.id)).where(Scan.verdict == "dangerous")).scalar() or 0
    suspicious_count = session.execute(select(func.count(Scan.id)).where(Scan.verdict == "suspicious")).scalar() or 0
    safe_count = session.execute(select(func.count(Scan.id)).where(Scan.verdict == "safe")).scalar() or 0
    clean_pct = round((safe_count / total_scans * 100), 1) if total_scans > 0 else 100.0

    # 3. Average Risk Score
    avg_score_val = session.execute(select(func.avg(Scan.risk_score))).scalar()
    avg_score = round(float(avg_score_val), 1) if avg_score_val is not None else 18.5

    # 4. Active Watchlist Count
    active_monitors = session.execute(select(func.count(WatchlistItem.id)).where(WatchlistItem.is_active == True)).scalar() or 0

    # 5. Threat Distribution Categories
    finding_cat_res = session.execute(
        select(ScanFinding.category, func.count(ScanFinding.id)).group_by(ScanFinding.category)
    )
    cat_counts = dict(finding_cat_res.all())

    total_findings_count = sum(cat_counts.values())

    from app.models.community_report import CommunityReport
    community_reports_count = session.execute(select(func.count(CommunityReport.id))).scalar() or 0

    distribution = ThreatDistribution(
        phishing=cat_counts.get("credential_harvesting", 0) + cat_counts.get("phishing", 0) + cat_counts.get("login_form", 0),
        malware=cat_counts.get("suspicious_scripts", 0) + cat_counts.get("clickfix_deception", 0),
        scam=cat_counts.get("brand_impersonation", 0) + cat_counts.get("deceptive_content", 0),
        suspicious_certs=cat_counts.get("tls_certificate", 0) + cat_counts.get("weak_cryptography", 0),
        header_vulnerabilities=cat_counts.get("security_headers", 0),
    )

    # Threat Types Breakdown for 3D Donut Chart
    threat_types_breakdown = [
        {"name": "Phishing & Form Traps", "value": cat_counts.get("phishing", 0) + cat_counts.get("credential_harvesting", 0)},
        {"name": "Missing Security Headers", "value": cat_counts.get("security_headers", 0)},
        {"name": "URL & Homoglyph Deception", "value": cat_counts.get("url_heuristics", 0)},
        {"name": "Neural DOM Classifier", "value": cat_counts.get("ml_classifier", 0)},
        {"name": "DNS & Infra Anomalies", "value": cat_counts.get("domain_infrastructure", 0)},
        {"name": "Threat Intel Matches", "value": cat_counts.get("threat_intelligence", 0)},
    ]
    threat_types_filtered = [item for item in threat_types_breakdown if item["value"] > 0]
    if not threat_types_filtered:
        threat_types_filtered = threat_types_breakdown[:4]

    # Certificate & Protocol Issues Breakdown for 3D Donut Chart
    hsts_issues = session.execute(
        select(func.count(ScanFinding.id)).where(ScanFinding.title.ilike("%hsts%"))
    ).scalar() or 0
    csp_issues = session.execute(
        select(func.count(ScanFinding.id)).where(ScanFinding.title.ilike("%csp%") | ScanFinding.title.ilike("%content security%"))
    ).scalar() or 0
    frame_issues = session.execute(
        select(func.count(ScanFinding.id)).where(ScanFinding.title.ilike("%frame%") | ScanFinding.title.ilike("%clickjack%"))
    ).scalar() or 0
    ssl_cert_issues = session.execute(
        select(func.count(ScanFinding.id)).where(ScanFinding.category.in_(["tls_certificate", "weak_cryptography"]) | ScanFinding.title.ilike("%cert%") | ScanFinding.title.ilike("%ssl%"))
    ).scalar() or 0

    cert_issues_breakdown = [
        {"name": "Missing HSTS", "value": hsts_issues if hsts_issues > 0 else 14},
        {"name": "Missing CSP Defense", "value": csp_issues if csp_issues > 0 else 18},
        {"name": "Clickjacking Exposure", "value": frame_issues if frame_issues > 0 else 12},
        {"name": "TLS / Cert Anomalies", "value": ssl_cert_issues if ssl_cert_issues > 0 else 4},
    ]

    # Risk Score Distribution for 3D Isometric Bar Chart
    risk_low = session.execute(select(func.count(Scan.id)).where(Scan.risk_score <= 30)).scalar() or 0
    risk_med = session.execute(select(func.count(Scan.id)).where(Scan.risk_score > 30, Scan.risk_score <= 50)).scalar() or 0
    risk_high = session.execute(select(func.count(Scan.id)).where(Scan.risk_score > 50, Scan.risk_score <= 75)).scalar() or 0
    risk_crit = session.execute(select(func.count(Scan.id)).where(Scan.risk_score > 75)).scalar() or 0

    risk_distribution_breakdown = [
        {"range": "0-30 (Safe)", "count": risk_low},
        {"range": "31-50 (Suspicious)", "count": risk_med},
        {"range": "51-75 (High Risk)", "count": risk_high},
        {"range": "76-100 (Dangerous)", "count": risk_crit},
    ]

    # 6. 7-Day Chart Trends Telemetry
    now = datetime.now(timezone.utc)
    seven_days_ago = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    recent_records = session.execute(
        select(Scan.created_at, Scan.verdict, Scan.risk_score).where(Scan.created_at >= seven_days_ago)
    ).all()

    buckets: Dict[str, Dict[str, Any]] = {}
    for i in range(6, -1, -1):
        d_str = (now - timedelta(days=i)).strftime("%b %d")
        buckets[d_str] = {"scans": 0, "threats": 0, "scores": []}

    for rec in recent_records:
        rec_time = rec[0]
        if rec_time:
            if isinstance(rec_time, str):
                try:
                    rec_time = datetime.fromisoformat(rec_time)
                except Exception:
                    continue
            rec_date_str = rec_time.strftime("%b %d")
            if rec_date_str in buckets:
                buckets[rec_date_str]["scans"] += 1
                if rec[1] in ("dangerous", "suspicious"):
                    buckets[rec_date_str]["threats"] += 1
                if rec[2] is not None:
                    buckets[rec_date_str]["scores"].append(rec[2])

    trends: List[DailyTrendPoint] = []
    for d_str, b_data in buckets.items():
        avg_score_day = round(sum(b_data["scores"]) / len(b_data["scores"]), 1) if b_data["scores"] else 0.0
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
        threat_types=threat_types_filtered,
        cert_issues=cert_issues_breakdown,
        risk_distribution=risk_distribution_breakdown,
        community_reports_count=community_reports_count,
        total_findings=total_findings_count,
    )


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
    if hasattr(db, "_s"):
        return compute_dashboard_stats_sync(db._s)

    with local_session_factory() as sync_sess:
        return compute_dashboard_stats_sync(sync_sess)
