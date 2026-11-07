"""
Tests for Dashboard Statistics and Telemetry Aggregation API.
"""

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select

from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.watchlist import WatchlistItem
from app.db.session import local_session_factory
from app.api.v1.dashboard import compute_dashboard_stats_sync


def test_dashboard_stats_calculation():
    """Verify aggregated metrics: total scans, clean ratio, verdict counts, categories."""
    session = local_session_factory()
    try:
        now = datetime.now(timezone.utc)
        s1 = Scan(
            id=uuid.uuid4(),
            input_url="https://safe-site-portal.com",
            normalized_url="https://safe-site-portal.com/",
            status="completed",
            verdict="safe",
            risk_score=12,
            created_at=now,
            updated_at=now,
        )
        s2 = Scan(
            id=uuid.uuid4(),
            input_url="https://bad-phish-domain.net",
            normalized_url="https://bad-phish-domain.net/",
            status="completed",
            verdict="dangerous",
            risk_score=90,
            created_at=now,
            updated_at=now,
        )
        session.add_all([s1, s2])

        f1 = ScanFinding(
            scan_id=s2.id,
            category="credential_harvesting",
            title="Password Theft Form",
            severity="critical",
            confidence=0.98,
            description="Phishing form detected",
            risk_points=40,
        )
        session.add(f1)
        session.commit()

        stats = compute_dashboard_stats_sync(session)

        assert stats.total_scans >= 2
        assert stats.malicious_detected >= 1
        assert stats.safe_detected >= 1
        assert stats.clean_percentage >= 0.0
        assert stats.threat_distribution.phishing >= 1
        assert len(stats.chart_trends) == 7
    finally:
        session.close()
