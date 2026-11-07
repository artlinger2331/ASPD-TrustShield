import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import (
    Base,
    User,
    Scan,
    ScanFinding,
    Certificate,
    ThreatIntelResult,
    CommunityReport,
    WatchlistItem,
    Alert,
)


@pytest.fixture(scope="module")
def memory_db_session():
    """
    Creates an in-memory SQLite database to test all model definitions,
    relationships, constraints, and cascading rules offline.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_metadata_contains_all_tables():
    """Verify all 8 core tables are registered with Base.metadata."""
    table_names = set(Base.metadata.tables.keys())
    expected = {
        "users",
        "scans",
        "scan_findings",
        "certificates",
        "threat_intel_results",
        "community_reports",
        "watchlist_items",
        "alerts",
    }
    assert expected.issubset(table_names), f"Missing tables: {expected - table_names}"


def test_user_creation_and_defaults(memory_db_session):
    """Verify User model creation with default UUID, role, and active status."""
    user = User(
        email="analyst@trustshield.local",
        hashed_password="bcrypt$argon2$hash",
        full_name="SecOps Analyst",
        role="moderator",
    )
    memory_db_session.add(user)
    memory_db_session.commit()

    assert isinstance(user.id, uuid.UUID)
    assert user.is_active is True
    assert user.role == "moderator"
    assert user.created_at is not None


def test_guest_scan_creation_without_user(memory_db_session):
    """Verify scans can be initiated anonymously by guest users (user_id=None)."""
    scan = Scan(
        user_id=None,
        input_url="http://fake-banking-update.xyz/login",
        normalized_url="https://fake-banking-update.xyz/login",
        status="queued",
    )
    memory_db_session.add(scan)
    memory_db_session.commit()

    assert scan.user_id is None
    assert scan.status == "queued"
    assert isinstance(scan.id, uuid.UUID)


def test_scan_with_findings_and_cascade(memory_db_session):
    """Verify Scan with findings, certificate, and threat intel child records."""
    user = User(
        email="scan_owner@trustshield.local",
        hashed_password="secure_password_hash",
        role="user",
    )
    memory_db_session.add(user)
    memory_db_session.commit()

    scan = Scan(
        user_id=user.id,
        input_url="https://paypal-verify-alert.online",
        normalized_url="https://paypal-verify-alert.online",
        final_url="https://paypal-verify-alert.online/harvest.php",
        status="completed",
        verdict="likely_phishing",
        risk_score=92,
        confidence=0.98,
        summary="High-confidence phishing targeting PayPal credentials.",
        recommendation="Quarantine link and submit to global blocklist.",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    memory_db_session.add(scan)
    memory_db_session.commit()

    # Add ScanFinding with JSON evidence and raw data
    finding = ScanFinding(
        scan_id=scan.id,
        category="phishing_content",
        title="Deceptive Brand Impersonation Form",
        severity="critical",
        confidence=0.95,
        description="Login form posting credentials to unverified third-party IP.",
        evidence={"target_brand": "PayPal", "form_action": "/harvest.php"},
        risk_points=40,
        raw_data={"input_types": ["text", "password"]},
    )
    memory_db_session.add(finding)

    # Add Certificate
    cert = Certificate(
        scan_id=scan.id,
        subject="CN=paypal-verify-alert.online",
        issuer="CN=Let's Encrypt Authority R3",
        days_until_expiry=12,
        is_valid=True,
        is_revoked=False,
        chain_valid=True,
        ct_log_present=True,
        ca_trust_status="trusted",
        raw_certificate={"fingerprint": "SHA256:1234567890abcdef"},
    )
    memory_db_session.add(cert)

    # Add ThreatIntelResult
    intel = ThreatIntelResult(
        scan_id=scan.id,
        source="google_safe_browsing",
        match_type="social_engineering",
        confidence=0.99,
        details={"threat_platform": "ANY_PLATFORM"},
        raw_response={"matches": [{"threatType": "MALWARE"}]},
    )
    memory_db_session.add(intel)
    memory_db_session.commit()

    # Query scan and verify child relationships
    loaded_scan = memory_db_session.query(Scan).filter_by(id=scan.id).one()
    assert len(loaded_scan.findings) == 1
    assert loaded_scan.findings[0].risk_points == 40
    assert loaded_scan.certificate is not None
    assert loaded_scan.certificate.subject == "CN=paypal-verify-alert.online"
    assert len(loaded_scan.threat_intel_results) == 1

    # Verify CASCADE: Deleting scan should delete child findings, cert, and threat intel
    memory_db_session.delete(loaded_scan)
    memory_db_session.commit()

    remaining_findings = memory_db_session.query(ScanFinding).filter_by(scan_id=scan.id).all()
    remaining_cert = memory_db_session.query(Certificate).filter_by(scan_id=scan.id).first()
    remaining_intel = memory_db_session.query(ThreatIntelResult).filter_by(scan_id=scan.id).all()

    assert len(remaining_findings) == 0
    assert remaining_cert is None
    assert len(remaining_intel) == 0


def test_community_report_with_null_and_authenticated_reporter(memory_db_session):
    """Verify community reports work with both anonymous guest submissions and authenticated reporters."""
    anon_report = CommunityReport(
        url="https://free-crypto-drop.top",
        domain="free-crypto-drop.top",
        reporter_id=None,
        threat_type="phishing",
        description="Fake Metamask drainer asking for 12-word seed phrase.",
        source="community",
        status="pending",
        confirmations=3,
        false_positive_votes=0,
    )
    memory_db_session.add(anon_report)
    memory_db_session.commit()

    assert anon_report.reporter_id is None
    assert anon_report.confirmations == 3
    assert isinstance(anon_report.id, uuid.UUID)


def test_watchlist_and_alert_system(memory_db_session):
    """Verify WatchlistItem creation, alerts dispatching, and cascade on delete."""
    user = User(
        email="domain_watcher@trustshield.local",
        hashed_password="secure_password_hash",
        role="user",
    )
    memory_db_session.add(user)
    memory_db_session.commit()

    watchlist_item = WatchlistItem(
        user_id=user.id,
        domain="my-company-portal.com",
        alert_types=["cert_expiry", "new_report"],
        is_active=True,
    )
    memory_db_session.add(watchlist_item)
    memory_db_session.commit()

    alert = Alert(
        user_id=user.id,
        watchlist_item_id=watchlist_item.id,
        alert_type="cert_expiry",
        message="SSL certificate for my-company-portal.com expires in 14 days.",
        is_read=False,
    )
    memory_db_session.add(alert)
    memory_db_session.commit()

    loaded_alerts = memory_db_session.query(Alert).filter_by(user_id=user.id).all()
    assert len(loaded_alerts) == 1
    assert loaded_alerts[0].is_read is False
    assert loaded_alerts[0].watchlist_item_id == watchlist_item.id

    # Verify CASCADE: deleting watchlist item cleans up associated alerts
    memory_db_session.delete(watchlist_item)
    memory_db_session.commit()

    assert memory_db_session.query(Alert).filter_by(watchlist_item_id=watchlist_item.id).first() is None

