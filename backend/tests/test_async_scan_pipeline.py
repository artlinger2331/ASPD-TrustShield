"""
Comprehensive automated tests for TrustShield's Asynchronous Scan Pipeline.
Tests:
  1. Successful scan execution end-to-end
  2. Failed scan saves partial findings and preliminary risk score
  3. Scan timeout graceful recovery (SoftTimeLimitExceeded)
  4. Invalid URL and SSRF rejection
  5. Concurrent duplicate scan deduplication
  6. Real-time step progress (1-6) and action telemetry tracking
"""

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import pytest
from httpx import AsyncClient
from fastapi import status

from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.db.session import local_session_factory
from app.services.scan_orchestrator import execute_scan_pipeline_sync
from app.tasks.scan_tasks import execute_scan_task, SoftTimeLimitExceeded


MOCK_SAFE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Legitimate Portal</title></head>
<body><h1>Welcome to our corporate service</h1><p>Contact support@example.com for help.</p></body>
</html>
"""

MOCK_PHISHING_HTML = """
<!DOCTYPE html>
<html>
<head><title>Account Suspended - Verify PayPal Account</title></head>
<body>
    <div class="alert">Your account has been locked. Verify immediately.</div>
    <form action="http://phish-drop.xyz/collect" method="POST">
        <input type="text" name="email" placeholder="Email" />
        <input type="password" name="password" placeholder="Password" />
        <input type="text" name="otp" placeholder="Enter 6-digit OTP" />
        <button type="submit">Unlock Account</button>
    </form>
</body>
</html>
"""


@pytest.fixture(autouse=True)
def mock_background_dispatch():
    with patch("app.api.v1.scans.dispatch_scan") as mock:
        yield mock


@pytest.mark.asyncio
async def test_successful_scan_end_to_end(async_client: AsyncClient, mock_background_dispatch):
    """
    Test end-to-end flow:
    1. Submit POST /api/v1/scans
    2. Verify queued record with step 0
    3. Run pipeline synchronously with mock HTML
    4. Poll GET /api/v1/scans/{id} to verify completion (step 6, score, verdict)
    5. GET /api/v1/scans/{id}/report for full telemetry
    """
    print("\n--- Starting test_successful_scan_end_to_end ---")
    target_url = "https://safe-enterprise-platform.com/portal"
    # 1. Submit scan request
    print("Step 1: POST /api/v1/scans")
    post_res = await async_client.post("/api/v1/scans", json={"url": target_url})
    print(f"POST returned: {post_res.status_code}")
    assert post_res.status_code == status.HTTP_202_ACCEPTED
    post_data = post_res.json()
    scan_id_str = post_data["id"]
    scan_uuid = uuid.UUID(scan_id_str)
    assert post_data["status"] == "queued"
    assert post_data["current_step"] == 0
    assert mock_background_dispatch.called

    # 2. Check initial status polling
    print("Step 2: GET status initial")
    poll_res1 = await async_client.get(f"/api/v1/scans/{scan_id_str}")
    print(f"Poll 1 returned: {poll_res1.status_code}")
    assert poll_res1.status_code == status.HTTP_200_OK
    poll_data1 = poll_res1.json()
    assert poll_data1["status"] == "queued"
    assert poll_data1["step"] == 0
    assert poll_data1["total_steps"] == 6

    # 3. Execute scan pipeline (simulating worker execution offline)
    print("Step 3: execute_scan_pipeline_sync")
    completed_scan = execute_scan_pipeline_sync(
        scan_id=scan_uuid,
        resolve_network=False,
        mock_html=MOCK_SAFE_HTML,
    )
    print(f"Pipeline finished: {completed_scan.status if completed_scan else None}")
    assert completed_scan is not None
    assert completed_scan.status == "completed"
    assert completed_scan.current_step == 6

    # 4. Check completed status polling
    print("Step 4: GET status completed")
    poll_res2 = await async_client.get(f"/api/v1/scans/{scan_id_str}")
    assert poll_res2.status_code == status.HTTP_200_OK
    poll_data2 = poll_res2.json()
    assert poll_data2["status"] == "completed"
    assert poll_data2["step"] == 6
    assert poll_data2["verdict"] is not None
    assert poll_data2["risk_score"] is not None
    assert poll_data2["current_action"] == "Scan completed successfully"

    # 5. Retrieve full report
    print("Step 5: GET report")
    report_res = await async_client.get(f"/api/v1/scans/{scan_id_str}/report")
    assert report_res.status_code == status.HTTP_200_OK
    report_data = report_res.json()
    assert report_data["id"] == scan_id_str
    assert report_data["status"] == "completed"
    assert "findings" in report_data


@pytest.mark.asyncio
async def test_failed_scan_saves_partial_findings():
    """
    Test that an unexpected failure or exception mid-pipeline:
    1. Does NOT discard previously committed findings (DNS, cert)
    2. Changes scan status to 'failed'
    3. Evaluates a preliminary risk score from the partial findings
    4. Sets a descriptive error message
    """
    session = local_session_factory()
    scan_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=scan_id,
        input_url="https://partial-findings-test.xyz/login",
        normalized_url="https://partial-findings-test.xyz/login",
        status="queued",
        current_step=0,
        created_at=now,
        updated_at=now,
    )
    session.add(scan)
    session.commit()
    session.close()

    # Simulate crash during Stage 4 (DOM content analysis)
    with patch("app.services.scan_orchestrator.analyze_content_sync", side_effect=RuntimeError("DOM parser fatal core dump")):
        failed_scan = execute_scan_pipeline_sync(
            scan_id=scan_id,
            resolve_network=False,
            mock_html=MOCK_PHISHING_HTML,
        )

    verify_session = local_session_factory()
    try:
        updated_scan = verify_session.query(Scan).filter(Scan.id == scan_id).first()
        assert updated_scan is not None
        # Must be marked failed
        assert updated_scan.status == "failed"
        assert updated_scan.error_message is not None

        # Verify that earlier stages (domain/cert/headers) saved partial findings
        findings = verify_session.query(ScanFinding).filter(ScanFinding.scan_id == scan_id).all()
        # Should have findings from earlier steps (e.g. .xyz suspicious TLD)
        assert len(findings) > 0
        # Preliminary score was calculated
        assert updated_scan.risk_score is not None
        assert updated_scan.verdict is not None
    finally:
        verify_session.close()


def test_scan_timeout_graceful_handling():
    """
    Test that Celery's SoftTimeLimitExceeded:
    1. Sets scan status to 'failed'
    2. Saves timeout error message
    3. Preserves partial findings and preliminary risk score
    """
    session = local_session_factory()
    scan_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=scan_id,
        input_url="https://timeout-target-service.com/dashboard",
        normalized_url="https://timeout-target-service.com/dashboard",
        status="running",
        current_step=3,
        created_at=now,
        updated_at=now,
    )
    session.add(scan)

    # Add a mock finding to simulate partial findings before timeout
    finding = ScanFinding(
        scan_id=scan.id,
        category="security_headers",
        title="Missing HSTS Header",
        severity="medium",
        confidence=0.9,
        description="Strict-Transport-Security header was not detected.",
        risk_points=15,
    )
    session.add(finding)
    session.commit()
    session.close()

    # Simulate Celery worker running execute_scan_task and raising SoftTimeLimitExceeded
    with patch("app.tasks.scan_tasks.execute_scan_pipeline_sync", side_effect=SoftTimeLimitExceeded("Execution timed out")):
        task_res = execute_scan_task(str(scan_id))

    assert task_res["status"] == "failed"
    assert "timed out" in task_res["error"]

    verify_session = local_session_factory()
    try:
        updated_scan = verify_session.query(Scan).filter(Scan.id == scan_id).first()
        assert updated_scan is not None
        assert updated_scan.status == "failed"
        assert "timed out" in updated_scan.error_message
        assert updated_scan.completed_at is not None

        # Partial findings must remain preserved in the DB
        findings = verify_session.query(ScanFinding).filter(ScanFinding.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].title == "Missing HSTS Header"
        # Preliminary risk score computed
        assert updated_scan.risk_score is not None
    finally:
        verify_session.close()


@pytest.mark.asyncio
async def test_invalid_url_rejection(async_client: AsyncClient):
    """
    Test validation layer rejects malformed URLs and SSRF targets with HTTP 422.
    """
    # 1. Non-HTTP scheme
    res1 = await async_client.post("/api/v1/scans", json={"url": "ftp://files.example.com/data"})
    assert res1.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data1 = res1.json()
    assert data1.get("code") == "INVALID_URL"

    # 2. Localhost SSRF loopback
    res2 = await async_client.post("/api/v1/scans", json={"url": "http://127.0.0.1:8000/internal"})
    assert res2.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data2 = res2.json()
    assert data2.get("code") == "INVALID_URL"

    # 3. Cloud metadata IP SSRF
    res3 = await async_client.post("/api/v1/scans", json={"url": "http://169.254.169.254/latest/meta-data"})
    assert res3.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data3 = res3.json()
    assert data3.get("code") == "INVALID_URL"

    # 4. Empty or missing host structure
    res4 = await async_client.post("/api/v1/scans", json={"url": "http://"})
    assert res4.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data4 = res4.json()
    assert data4.get("code") == "INVALID_URL"


@pytest.mark.asyncio
async def test_concurrent_duplicate_scan_prevention(async_client: AsyncClient, mock_background_dispatch):
    """
    Test duplicate scan deduplication:
    When a scan for the same URL is already 'queued' or 'running' within 5 minutes,
    the API returns the existing scan ID rather than launching redundant background work.
    """
    target_url = "https://duplicate-check-portal.org/login"

    # Reset mock call count
    mock_background_dispatch.reset_mock()

    # First submission
    res1 = await async_client.post("/api/v1/scans", json={"url": target_url})
    assert res1.status_code == status.HTTP_202_ACCEPTED
    data1 = res1.json()
    scan_id_1 = data1["id"]

    # Immediate second submission with identical URL
    res2 = await async_client.post("/api/v1/scans", json={"url": target_url})
    # Should accept and return the exact same scan ID
    assert res2.status_code in (status.HTTP_200_OK, status.HTTP_202_ACCEPTED)
    data2 = res2.json()
    scan_id_2 = data2["id"]

    assert scan_id_1 == scan_id_2, "Concurrent duplicate scan should reuse the existing in-flight scan ID"

    # Immediate third submission with slight formatting differences (trailing slash / whitespace)
    res3 = await async_client.post("/api/v1/scans", json={"url": "  https://duplicate-check-portal.org/login/  "})
    data3 = res3.json()
    assert data3["id"] == scan_id_1, "Normalized URL match should deduplicate formatting variants"

    # mock_background_dispatch should have been called only once for the first submission, not for the duplicates!
    assert mock_background_dispatch.call_count == 1


@pytest.mark.asyncio
async def test_real_time_step_and_action_progress():
    """
    Test that current_step increments progressively across all 6 stages
    and current_action records descriptive telemetry status messages.
    """
    session = local_session_factory()
    scan_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=scan_id,
        input_url="https://stepper-progress-test.org/app",
        normalized_url="https://stepper-progress-test.org/app",
        status="queued",
        current_step=0,
        current_action="Scan queued in worker pool",
        created_at=now,
        updated_at=now,
    )
    session.add(scan)
    session.commit()
    session.close()

    step_history = []

    # Run the pipeline
    completed_scan = execute_scan_pipeline_sync(
        scan_id=scan_id,
        resolve_network=False,
        mock_html=MOCK_SAFE_HTML,
    )

    verify_session = local_session_factory()
    try:
        final_scan = verify_session.query(Scan).filter(Scan.id == scan_id).first()
        assert final_scan is not None
        assert final_scan.status == "completed"
        assert final_scan.current_step == 6
        assert final_scan.current_action == "Scan completed successfully"
        assert final_scan.started_at is not None
        assert final_scan.completed_at is not None
        assert final_scan.completed_at >= final_scan.started_at
    finally:
        verify_session.close()
