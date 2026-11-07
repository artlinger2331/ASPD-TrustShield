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
from app.api.v1.dashboard import get_dashboard_stats


import asyncio

def test_dashboard_stats_calculation():
    """Verify aggregated metrics: total scans, clean ratio, verdict counts, categories."""
    async def _run():
        print('1. in _run', flush=True)
        session = local_session_factory()
        try:
            print('2. adding records', flush=True)
            now = datetime.now(timezone.utc)
            s1 = Scan(
                id=uuid.uuid4(),
                input_url="https://safe-site.com",
                normalized_url="https://safe-site.com/",
                status="completed",
                verdict="safe",
                risk_score=12,
                created_at=now,
                updated_at=now,
            )
            s2 = Scan(
                id=uuid.uuid4(),
                input_url="https://bad-phish.net",
                normalized_url="https://bad-phish.net/",
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
            print('3. committing', flush=True)
            session.commit()
            print('4. committed', flush=True)

            from app.db.session import AsyncSessionFallback
            fallback = AsyncSessionFallback(session)
            print('5. calling get_dashboard_stats', flush=True)
            stats = await get_dashboard_stats(db=fallback)
            print('6. got stats', flush=True)

            assert stats.total_scans >= 2
            assert stats.malicious_detected >= 1
            assert stats.safe_detected >= 1
            assert stats.clean_percentage >= 0.0
            assert stats.threat_distribution.phishing >= 1
            assert len(stats.chart_trends) == 7
        finally:
            session.close()

    asyncio.run(_run())
