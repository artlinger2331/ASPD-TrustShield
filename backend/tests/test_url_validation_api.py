"""
Integration tests for URL validation API (/api/v1/scans/validate)
and Scan Pipeline finding persistence.
"""

import uuid
import pytest
from httpx import AsyncClient

from app.db.session import local_session_factory
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.services.scan_orchestrator import execute_scan_pipeline_sync


@pytest.mark.asyncio
async def test_api_validate_valid_url(async_client: AsyncClient):
    """Verify POST /api/v1/scans/validate returns structured components for valid public URL."""
    resp = await async_client.post(
        "/api/v1/scans/validate",
        json={"url": "https://docs.github.com/en/actions?query=workflow#summary", "resolve_dns": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["normalized_url"] == "https://docs.github.com/en/actions?query=workflow"
    assert data["error_message"] is None
    assert data["parts"]["scheme"] == "https"
    assert data["parts"]["host"] == "docs.github.com"
    assert data["parts"]["registered_domain"] == "github.com"
    assert data["parts"]["subdomain"] == "docs"
    assert data["parts"]["tld"] == "com"
    assert data["parts"]["path"] == "/en/actions"
    assert data["parts"]["query_params"]["query"] == "workflow"
    assert data["parts"]["fragment"] == "summary"
    assert data["heuristics"]["is_ip"] is False
    assert data["heuristics"]["is_shortener"] is False


@pytest.mark.asyncio
async def test_api_validate_ssrf_blocked_urls(async_client: AsyncClient):
    """Verify that private loopback and cloud metadata targets are rejected with is_valid=False."""
    # Loopback
    resp1 = await async_client.post(
        "/api/v1/scans/validate",
        json={"url": "http://127.0.0.1:8000/api/v1/health", "resolve_dns": False},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["is_valid"] is False
    assert "SSRF Protection" in data1["error_message"]

    # AWS/GCP instance metadata
    resp2 = await async_client.post(
        "/api/v1/scans/validate",
        json={"url": "http://169.254.169.254/latest/meta-data/", "resolve_dns": False},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["is_valid"] is False
    assert "SSRF Protection" in data2["error_message"]

    # Localhost name
    resp3 = await async_client.post(
        "/api/v1/scans/validate",
        json={"url": "http://localhost/admin", "resolve_dns": False},
    )
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert data3["is_valid"] is False
    assert "Prohibited local/internal hostname" in data3["error_message"]


@pytest.mark.asyncio
async def test_api_validate_heuristic_findings_extraction(async_client: AsyncClient):
    """Verify deep heuristic flags (keywords, suspicious TLD, excessive subdomains) are extracted."""
    suspicious_target = "https://login.verify.update.portal-security.xyz/account/recovery?claim=reward"
    resp = await async_client.post(
        "/api/v1/scans/validate",
        json={"url": suspicious_target, "resolve_dns": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    h = data["heuristics"]
    assert h["has_suspicious_tld"] is True
    assert h["has_excessive_subdomains"] is True
    assert h["subdomain_count"] == 3
    assert len(h["suspicious_keywords_found"]) >= 4
    assert "login" in h["suspicious_keywords_found"]
    assert "verify" in h["suspicious_keywords_found"]
    assert "recovery" in h["suspicious_keywords_found"]
    assert h["heuristic_risk_score"] >= 40
    assert len(data["findings"]) >= 3


@pytest.mark.asyncio
async def test_api_validate_embedded_credentials(async_client: AsyncClient):
    """Verify embedded userinfo credentials are stripped from normalized_url and flagged."""
    resp = await async_client.post(
        "/api/v1/scans/validate",
        json={"url": "https://admin:SecretPassword123@target-website.com/login", "resolve_dns": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert "admin:SecretPassword123@" not in data["normalized_url"]
    assert data["heuristics"]["has_embedded_credentials"] is True
    assert any(f["title"] == "Deceptive Embedded Credentials in URL" for f in data["findings"])


def test_scan_pipeline_persists_url_heuristics():
    """Verify that execute_scan_pipeline_sync persists URL heuristic findings into the database."""
    session = local_session_factory()
    scan_id = uuid.uuid4()
    suspicious_url = "https://login.secure.verify.fakebank.xyz/account/recovery"

    scan = Scan(
        id=scan_id,
        input_url=suspicious_url,
        normalized_url=suspicious_url,
        status="queued",
    )
    session.add(scan)
    session.commit()

    try:
        # Run pipeline synchronously with mocked network
        completed_scan = execute_scan_pipeline_sync(
            scan_id=scan_id,
            resolve_network=False,
            mock_html="<html><body><p>Fake bank portal</p></body></html>",
        )
        assert completed_scan is not None
        assert completed_scan.status == "completed"

        # Query scan findings for category='url_heuristics'
        findings = session.query(ScanFinding).filter(
            ScanFinding.scan_id == scan_id,
            ScanFinding.category == "url_heuristics",
        ).all()

        assert len(findings) >= 2
        titles = {f.title for f in findings}
        assert "Deceptive Phishing Keywords in URL" in titles
        assert "Suspicious / High-Abuse Top-Level Domain" in titles
        assert "Excessive Subdomain Stacking" in titles
    finally:
        # Clean up test scan
        session.query(ScanFinding).filter(ScanFinding.scan_id == scan_id).delete()
        session.query(Scan).filter(Scan.id == scan_id).delete()
        session.commit()
        session.close()
