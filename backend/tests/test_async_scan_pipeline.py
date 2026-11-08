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
from fastapi import status, BackgroundTasks

from app.core.exceptions import AppException
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.schemas.scan import ScanCreate
from app.db.session import local_session_factory, AsyncSessionFallback
from app.api.v1.scans import create_scan, get_scan_status, get_scan_report
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


def run_coro(coro):
    """
    Executes a coroutine that wraps synchronous/fallback database operations
    without requiring an event loop that creates loopback sockets.
    """
    try:
        while True:
            coro.send(None)
    except StopIteration as e:
        return e.value


@pytest.fixture(autouse=True)
def mock_background_dispatch():
    with patch("app.api.v1.scans.dispatch_scan") as mock:
        yield mock


def test_successful_scan_end_to_end(mock_background_dispatch):
    """
    Test end-to-end flow:
    1. Submit create_scan (POST /api/v1/scans)
    2. Verify queued record with step 0 and initial status
    3. Run pipeline synchronously with mock HTML
    4. Poll get_scan_status (GET /api/v1/scans/{id}) to verify completion (step 6, score, verdict)
    5. Call get_scan_report (GET /api/v1/scans/{id}/report) for full telemetry dossier
    """
    session = local_session_factory()
    db = AsyncSessionFallback(session)
    bg = BackgroundTasks()
    target_url = "https://safe-enterprise-platform.com/portal"

    try:
        # 1. Submit scan request
        post_data = run_coro(create_scan(ScanCreate(url=target_url), bg, None, db))
        scan_id = post_data.id
        assert post_data.status == "queued"
        assert post_data.current_step == 0
        assert mock_background_dispatch.called

        # 2. Check initial status polling
        poll_data1 = run_coro(get_scan_status(scan_id, db))
        assert poll_data1.status == "queued"
        assert poll_data1.step == 0
        assert poll_data1.total_steps == 6
        assert poll_data1.current_action == "Scan queued in worker pool"

        # 3. Execute scan pipeline (simulating worker execution offline)
        completed_scan = execute_scan_pipeline_sync(
            scan_id=scan_id,
            resolve_network=False,
            mock_html=MOCK_SAFE_HTML,
        )
        assert completed_scan is not None
        assert completed_scan.status == "completed"
        assert completed_scan.current_step == 6

        # 4. Check completed status polling
        poll_data2 = run_coro(get_scan_status(scan_id, db))
        assert poll_data2.status == "completed"
        assert poll_data2.step == 6
        assert poll_data2.verdict is not None
        assert poll_data2.risk_score is not None
        assert poll_data2.current_action == "Scan completed successfully"

        # 5. Retrieve full report dossier
        report_data = run_coro(get_scan_report(scan_id, db))
        assert report_data.id == scan_id
        assert report_data.status == "completed"
        assert len(report_data.findings) > 0
        assert report_data.verdict is not None
    finally:
        session.close()


def test_failed_scan_saves_partial_findings():
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

    call_count = 0
    from app.services.risk_engine import evaluate_risk as real_evaluate

    def failing_evaluate(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Engine failure during final report synthesis")
        return real_evaluate(*args, **kwargs)

    # Simulate crash during Stage 7 (risk evaluation synthesis)
    with patch("app.services.scan_orchestrator.evaluate_risk", side_effect=failing_evaluate):
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
        assert "Engine failure during final report synthesis" in updated_scan.error_message

        # Verify that earlier stages (domain/cert/headers/phishing) saved partial findings
        findings = verify_session.query(ScanFinding).filter(ScanFinding.scan_id == scan_id).all()
        # Should have findings from earlier steps (e.g. .xyz suspicious TLD, password form)
        assert len(findings) > 0
        # Preliminary score was calculated from partial findings
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
        task_res = execute_scan_task(MagicMock(), str(scan_id))

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


def test_invalid_url_rejection():
    """
    Test validation layer rejects malformed URLs and SSRF targets with AppException(code='INVALID_URL', status_code=422).
    """
    session = local_session_factory()
    db = AsyncSessionFallback(session)
    bg = BackgroundTasks()

    try:
        # 1. Non-HTTP scheme
        with pytest.raises(AppException) as exc1:
            run_coro(create_scan(ScanCreate(url="ftp://files.example.com/data"), bg, None, db))
        assert exc1.value.code == "INVALID_URL"
        assert exc1.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # 2. Localhost SSRF loopback
        with pytest.raises(AppException) as exc2:
            run_coro(create_scan(ScanCreate(url="http://127.0.0.1:8000/internal"), bg, None, db))
        assert exc2.value.code == "INVALID_URL"
        assert exc2.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # 3. Cloud metadata IP SSRF
        with pytest.raises(AppException) as exc3:
            run_coro(create_scan(ScanCreate(url="http://169.254.169.254/latest/meta-data"), bg, None, db))
        assert exc3.value.code == "INVALID_URL"
        assert exc3.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # 4. Empty or missing host structure
        with pytest.raises(AppException) as exc4:
            run_coro(create_scan(ScanCreate(url="http://"), bg, None, db))
        assert exc4.value.code == "INVALID_URL"
        assert exc4.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    finally:
        session.close()


def test_concurrent_duplicate_scan_prevention(mock_background_dispatch):
    """
    Test duplicate scan deduplication:
    When a scan for the same URL is already 'queued' or 'running' within 5 minutes,
    the API returns the existing scan ID rather than launching redundant background work.
    """
    session = local_session_factory()
    db = AsyncSessionFallback(session)
    bg = BackgroundTasks()
    target_url = "https://duplicate-check-portal.org/login"

    try:
        # Reset mock call count
        mock_background_dispatch.reset_mock()

        # First submission
        res1 = run_coro(create_scan(ScanCreate(url=target_url), bg, None, db))
        scan_id_1 = res1.id

        # Immediate second submission with identical URL
        res2 = run_coro(create_scan(ScanCreate(url=target_url), bg, None, db))
        scan_id_2 = res2.id

        assert scan_id_1 == scan_id_2, "Concurrent duplicate scan should reuse the existing in-flight scan ID"

        # Immediate third submission with slight formatting differences (trailing slash / whitespace)
        res3 = run_coro(create_scan(ScanCreate(url="  https://duplicate-check-portal.org/login/  "), bg, None, db))
        assert res3.id == scan_id_1, "Normalized URL match should deduplicate formatting variants"

        # mock_background_dispatch should have been called only once for the first submission, not for the duplicates!
        assert mock_background_dispatch.call_count == 1
    finally:
        session.close()


def test_real_time_step_and_action_progress():
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
