"""
Unit & Integration Tests for Milestone S1 & S2 Stabilization.
Tests User OAuth fields, Watchlist telemetry columns, Celery configuration,
and Scan dispatcher / Stale scan reaper watchdog.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import select

from app.models.user import User
from app.models.watchlist import WatchlistItem
from app.models.scan import Scan
from app.db.session import local_session_factory
from app.core.celery_app import celery_app, is_redis_available
from app.tasks.scan_tasks import dispatch_scan
from app.tasks.maintenance import reap_stale_scans


def test_user_model_oauth_fields():
    """Verify User model supports OAuth accounts without password requirement."""
    with local_session_factory() as session:
        unique_email = f"oauth_user_{uuid.uuid4().hex[:8]}@example.com"
        oauth_user = User(
            email=unique_email,
            hashed_password=None,
            auth_provider="google",
            oauth_id="google_sub_12345",
            avatar_url="https://lh3.googleusercontent.com/a/photo.jpg",
            full_name="Google Tester",
            role="user",
            is_active=True,
        )
        session.add(oauth_user)
        session.commit()
        session.refresh(oauth_user)

        assert oauth_user.id is not None
        assert oauth_user.hashed_password is None
        assert oauth_user.auth_provider == "google"
        assert oauth_user.oauth_id == "google_sub_12345"
        assert oauth_user.avatar_url == "https://lh3.googleusercontent.com/a/photo.jpg"


def test_watchlist_telemetry_columns():
    """Verify WatchlistItem model supports cached risk score and cert days."""
    with local_session_factory() as session:
        # Create user
        user = User(
            email=f"wl_user_{uuid.uuid4().hex[:8]}@example.com",
            full_name="Watchlist Tester",
            auth_provider="local",
            role="user",
        )
        session.add(user)
        session.commit()

        item = WatchlistItem(
            user_id=user.id,
            domain=f"test-{uuid.uuid4().hex[:6]}.org",
            last_risk_score=85,
            last_verdict="dangerous",
            cert_days_left=14,
            is_active=True,
        )
        session.add(item)
        session.commit()
        session.refresh(item)

        assert item.last_risk_score == 85
        assert item.last_verdict == "dangerous"
        assert item.cert_days_left == 14


def test_celery_app_configuration():
    """Verify Celery app configurations and task registration."""
    assert celery_app.main == "trustshield"
    assert celery_app.conf.timezone == "UTC"
    assert celery_app.conf.task_acks_late is True
    assert "app.tasks.scan_tasks.execute_scan_task" in celery_app.tasks
    assert "app.tasks.maintenance.reap_stale_scans_task" in celery_app.tasks


def test_dispatch_scan_routing():
    """Verify dispatch_scan routes to in-process or celery depending on redis state."""
    test_id = uuid.uuid4()
    # Test dispatch without redis (should return in_process or celery cleanly without throwing)
    mode = dispatch_scan(test_id, background_tasks=None)
    assert mode in ("celery", "sync_direct", "in_process")


def test_reap_stale_scans_watchdog():
    """Verify reaper transitions older queued/running scans to timeout."""
    with local_session_factory() as session:
        stale_id = uuid.uuid4()
        old_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        stale_scan = Scan(
            id=stale_id,
            input_url="https://stale-example.com",
            normalized_url="https://stale-example.com",
            status="running",
            created_at=old_time,
            updated_at=old_time,
        )
        session.add(stale_scan)
        session.commit()

    # Run reaper
    reaped = reap_stale_scans(stale_minutes=5)
    assert reaped >= 1

    with local_session_factory() as session:
        refreshed = session.get(Scan, stale_id)
        assert refreshed.status == "timeout"
        assert "timed out" in refreshed.error_message

