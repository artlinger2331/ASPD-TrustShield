"""
Unit and integration tests for Phase 3 API endpoints:
1. Community Reports & Voting
2. Domain Watchlist & Alerts
3. AI Security Assistant
"""

import uuid
from datetime import datetime, timezone
import pytest
from app.db.session import local_session_factory
from app.models.user import User
from app.models.community_report import CommunityReport
from app.models.watchlist import WatchlistItem
from app.models.alert import Alert
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.api.v1.ai_assistant import generate_contextual_response


def test_community_report_workflow_sync():
    """Verify community report creation, status transitions, and voting mechanics."""
    session = local_session_factory()
    try:
        report = CommunityReport(
            url="https://fake-banking-portal.top/login",
            domain="fake-banking-portal.top",
            threat_type="phishing",
            description="Replicates online banking portal and requests debit card number and PIN.",
            status="pending",
            confirmations=1,
            false_positive_votes=0,
        )
        session.add(report)
        session.commit()
        session.refresh(report)

        assert report.id is not None
        assert report.status == "pending"
        assert report.confirmations == 1

        # Simulate two community confirmation upvotes
        report.confirmations += 2
        if report.confirmations >= 3 and report.status == "pending":
            report.status = "verified"

        session.commit()
        session.refresh(report)

        assert report.status == "verified"
        assert report.confirmations == 3
    finally:
        session.close()


def test_watchlist_and_alert_sync():
    """Verify domain watchlisting and alert generation."""
    session = local_session_factory()
    try:
        # Create test user
        user = User(
            email=f"watchtest_{uuid.uuid4().hex[:8]}@example.com",
            hashed_password="hashed_password",
            full_name="Watchlist Test User",
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        # Add domain to watchlist
        item = WatchlistItem(
            user_id=user.id,
            domain="monitored-domain.com",
            alert_types=["cert_expiry", "new_report"],
            is_active=True,
            last_checked_at=datetime.now(timezone.utc),
        )
        session.add(item)
        session.commit()
        session.refresh(item)

        # Generate alert for watchlisted item
        alert = Alert(
            user_id=user.id,
            watchlist_item_id=item.id,
            alert_type="cert_expiry",
            message="TLS certificate for monitored-domain.com expires in 12 days.",
            is_read=False,
        )
        session.add(alert)
        session.commit()
        session.refresh(alert)

        assert alert.id is not None
        assert alert.is_read is False

        # Mark alert as read
        alert.is_read = True
        session.commit()
        session.refresh(alert)
        assert alert.is_read is True
    finally:
        session.close()


def test_ai_security_assistant_contextual_response():
    """Verify AI Security Assistant contextualizes reasoning based on scan telemetry."""
    # Test 1: General inquiry
    resp_text, ctx_used, tgt, vrd, actions, srcs = generate_contextual_response("What is HSTS?")
    assert "Strict-Transport-Security" in resp_text
    assert ctx_used is False

    # Test 2: Incident response inquiry
    resp_text, ctx_used, tgt, vrd, actions, srcs = generate_contextual_response("I entered my password on a phishing site")
    assert "Incident Response Checklist" in resp_text
    assert len(actions) >= 2

    # Test 3: Contextual scan inquiry
    mock_scan = Scan(
        id=uuid.uuid4(),
        input_url="https://paypal-verify-account.top",
        normalized_url="https://paypal-verify-account.top",
        verdict="dangerous",
        risk_score=92,
        summary="High-risk brand impersonation of PayPal detected on suspicious TLD.",
        recommendation="Do not enter credentials on this site.",
    )
    resp_text, ctx_used, tgt, vrd, actions, srcs = generate_contextual_response("Why is this site dangerous?", scan=mock_scan)
    assert ctx_used is True
    assert "DANGEROUS" in resp_text
    assert "92/100" in resp_text

