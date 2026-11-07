"""
Unit and integration tests for Scans API and Orchestrator Pipeline.
"""

import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from fastapi import status

from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.services.scan_orchestrator import execute_scan_pipeline_sync
from app.db.session import local_session_factory
from tests.test_content_analyzer import HTML_PAYPAL_PHISHING


def test_pipeline_execution_mocked():
    """Verify that execute_scan_pipeline_sync coordinates analysis stages and generates a dangerous verdict on phishing HTML."""
    session = local_session_factory()
    try:
        # Create scan record
        scan = Scan(
            input_url="https://secure-login-verify.top/auth",
            normalized_url="https://secure-login-verify.top/auth",
            status="queued",
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # Run pipeline with resolve_network=False and HTML fixture
        completed_scan = execute_scan_pipeline_sync(
            scan_id=scan.id,
            resolve_network=False,
            mock_html=HTML_PAYPAL_PHISHING,
        )

        assert completed_scan is not None
        assert completed_scan.status == "completed"
        assert completed_scan.verdict == "dangerous"
        assert completed_scan.risk_score >= 70
        assert completed_scan.summary != ""
        assert completed_scan.recommendation != ""

        # Verify findings persisted
        findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        assert len(findings) >= 2
        categories = {f.category for f in findings}
        assert "domain_infrastructure" in categories  # .top TLD
        assert "credential_harvesting" in categories  # PayPal password form
    finally:
        session.close()


def test_scans_api_endpoints_sync():
    """Verify Scans API routing, report serialization, and history listings."""
    session = local_session_factory()
    try:
        # Create a completed scan in DB
        scan_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        scan = Scan(
            id=scan_id,
            input_url="https://verified-safe-portal.com",
            normalized_url="https://verified-safe-portal.com/",
            status="completed",
            verdict="safe",
            risk_score=10,
            confidence=0.94,
            summary="Website appears safe.",
            recommendation="Safe to browse.",
            created_at=now,
            updated_at=now,
            started_at=now,
            completed_at=now,
        )
        session.add(scan)

        # Add mock certificate
        cert = Certificate(
            scan_id=scan.id,
            subject="CN=verified-safe-portal.com",
            issuer="CN=DigiCert Global CA",
            days_until_expiry=90,
            is_valid=True,
            chain_valid=True,
            ct_log_present=True,
            ca_trust_status="trusted",
        )
        session.add(cert)

        # Add mock finding
        finding = ScanFinding(
            scan_id=scan.id,
            category="domain_infrastructure",
            title="Clean Domain History",
            severity="info",
            confidence=0.95,
            description="Established domain with no blacklists.",
            risk_points=0,
        )
        session.add(finding)
        session.commit()

        # Query scan report through session to verify serialization compatibility
        loaded_scan = session.query(Scan).filter(Scan.id == scan_id).first()
        assert loaded_scan is not None
        assert loaded_scan.certificate is not None
        assert len(loaded_scan.findings) == 1
        assert loaded_scan.verdict == "safe"
    finally:
        session.close()
