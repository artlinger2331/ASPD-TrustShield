"""
Comprehensive Integration Tests for TrustShield ML URL Classifier Pipeline Integration.

Verifies:
1. End-to-end scan pipeline invocation with mocked ML predictions.
2. Persistence of ML classification findings (category='ml_classifier', evidence, probability, version).
3. Retrieval of ML classification via GET /api/v1/scans/{id}/report.
4. Pipeline resilience and fault isolation (ML exception does not crash scan).
5. Feature flag toggle (ENABLE_ML_CLASSIFICATION=False) graceful bypass.
6. Thread-safe prediction caching and TTL expiration behavior.
7. Dynamic risk engine weighting and score attribution with configurable ML_RISK_WEIGHT.
8. Benign URL classification handling and severity mapping.
"""

import time
import uuid
from unittest.mock import patch, MagicMock
import pytest

from app.core.config import settings
from app.db.session import local_session_factory, AsyncSessionFallback
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult
from app.services.scan_orchestrator import execute_scan_pipeline_sync
from app.services.risk_engine import evaluate_risk
from app.api.v1.scans import get_scan_report
from app.ml.predict import (
    URLPredictionResult,
    TopFeatureContribution,
    PredictionCache,
    URLClassifier,
)
from app.schemas.ml_classification import MLClassificationResult, MLFeatureContribution


def run_coro(coro):
    """
    Executes a coroutine that wraps synchronous/fallback database operations.
    """
    try:
        while True:
            coro.send(None)
    except StopIteration as e:
        return e.value


@pytest.fixture
def mock_phishing_prediction():
    return URLPredictionResult(
        url="http://192.168.1.1/paypal/login-verification",
        label="phishing",
        is_phishing=True,
        probability=0.94,
        confidence=0.91,
        model_version="v1.0.0-mock",
        feature_schema_version="v1.0.0",
        top_contributing_features=[
            TopFeatureContribution(
                feature_name="domain_entropy",
                feature_value=4.85,
                contribution=0.35,
                description="High Shannon entropy in domain structure",
            ),
            TopFeatureContribution(
                feature_name="has_ip_address",
                feature_value=1.0,
                contribution=0.28,
                description="Host uses naked IP address notation",
            ),
        ],
        raw_features={
            "domain_entropy": 4.85,
            "has_ip_address": 1.0,
            "url_length": 68,
            "suspicious_keyword_count": 3,
        },
    )


@pytest.fixture
def mock_benign_prediction():
    return URLPredictionResult(
        url="https://legitimate-corp.com/about",
        label="benign",
        is_phishing=False,
        probability=0.03,
        confidence=0.96,
        model_version="v1.0.0-mock",
        feature_schema_version="v1.0.0",
        top_contributing_features=[
            TopFeatureContribution(
                feature_name="domain_age_days",
                feature_value=4500,
                contribution=-0.42,
                description="Long-standing established domain registration",
            ),
        ],
        raw_features={
            "domain_entropy": 2.1,
            "has_ip_address": 0.0,
            "url_length": 22,
            "suspicious_keyword_count": 0,
        },
    )


def test_scan_pipeline_executes_with_mocked_ml_prediction(mock_phishing_prediction):
    """
    Test 1: Verify the scan pipeline invokes ML classifier, persists finding,
    and returns ml_result in scan report response.
    """
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="http://192.168.1.1/paypal/login-verification",
            normalized_url="http://192.168.1.1/paypal/login-verification",
            status="queued",
            current_step=0,
            current_action="Queued",
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

        with patch.object(URLClassifier, "predict", return_value=mock_phishing_prediction):
            completed_scan = execute_scan_pipeline_sync(scan_id=scan_id, resolve_network=False)

        assert completed_scan.status == "completed"
        assert completed_scan.risk_score is not None

        # Verify ScanFinding table record for ml_classifier
        ml_finding = (
            session.query(ScanFinding)
            .filter(ScanFinding.scan_id == scan_id, ScanFinding.category == "ml_classifier")
            .first()
        )
        assert ml_finding is not None
        assert ml_finding.severity in ("high", "critical")
        assert ml_finding.evidence["predicted_label"] == "phishing"
        assert ml_finding.evidence["phishing_probability"] >= 0.5
        assert ml_finding.evidence["model_version"] == "v1.0.0-mock"
        assert len(ml_finding.evidence["top_indicators"]) > 0

        # Verify ScanReportResponse includes ml_result
        async_db = AsyncSessionFallback(session)
        report = run_coro(get_scan_report(scan_id=scan_id, db=async_db))

        assert report.ml_result is not None
        assert report.ml_result.predicted_label == "phishing"
        assert report.ml_result.is_phishing is True
        assert report.ml_result.phishing_probability >= 0.5
        assert report.ml_result.model_version == "v1.0.0-mock"
        assert len(report.ml_result.top_contributing_features) > 0
    finally:
        session.close()


def test_scan_pipeline_resilience_on_ml_failure():
    """
    Test 2: Verify ML failure does NOT fail the entire scan.
    Even if ML classifier throws an exception, the scan completes successfully.
    """
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="https://secure-portal-test.com/login",
            normalized_url="https://secure-portal-test.com/login",
            status="queued",
            current_step=0,
            current_action="Queued",
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

        with patch("app.services.scan_orchestrator.classify_url", side_effect=RuntimeError("ML engine GPU out of memory")):
            completed_scan = execute_scan_pipeline_sync(scan_id=scan_id, resolve_network=False)

        # Scan completes despite ML crash
        assert completed_scan.status == "completed"
        assert completed_scan.verdict in ("safe", "suspicious", "dangerous")
        assert completed_scan.risk_score is not None
    finally:
        session.close()


def test_feature_flag_disables_ml_classification():
    """
    Test 3: Verify setting ENABLE_ML_CLASSIFICATION=False bypasses ML classifier execution.
    """
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="https://example.com/test",
            normalized_url="https://example.com/test",
            status="queued",
            current_step=0,
            current_action="Queued",
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

        with patch.object(settings, "ENABLE_ML_CLASSIFICATION", False):
            with patch("app.analyzers.ml_classifier.classify_url") as mock_classify:
                completed_scan = execute_scan_pipeline_sync(scan_id=scan_id, resolve_network=False)

        assert completed_scan.status == "completed"
        # Since ENABLE_ML_CLASSIFICATION is false, classify_url returns None and is not executed
        ml_finding = (
            session.query(ScanFinding)
            .filter(ScanFinding.scan_id == scan_id, ScanFinding.category == "ml_classifier")
            .first()
        )
        assert ml_finding is None
    finally:
        session.close()


def test_prediction_caching_and_ttl():
    """
    Test 4: Verify thread-safe PredictionCache saves, hits, and expires entries.
    """
    cache = PredictionCache(default_ttl_seconds=1)
    res = URLPredictionResult(
        url="https://cache-test.org/phish",
        label="phishing",
        is_phishing=True,
        probability=0.88,
        confidence=0.85,
        model_version="v1.0.0-cache",
        feature_schema_version="v1.0.0",
        top_contributing_features=[],
        raw_features={"test": 1},
    )

    cache.set("https://cache-test.org/phish", "v1.0.0-cache", res)

    # Cache hit
    cached = cache.get("https://cache-test.org/phish", "v1.0.0-cache")
    assert cached is not None
    assert cached.probability == 0.88
    assert cached.cached is True

    # Cache miss on unknown URL
    assert cache.get("https://unknown.org", "v1.0.0-cache") is None

    # TTL Expiration test
    time.sleep(1.2)
    expired = cache.get("https://cache-test.org/phish", "v1.0.0-cache")
    assert expired is None


def test_risk_engine_configurable_ml_weight():
    """
    Test 5: Verify risk engine recalculates composite score with configurable ML_RISK_WEIGHT.
    """
    mock_ml = MLClassificationResult(
        url="https://suspicious-test.com",
        is_phishing=True,
        phishing_probability=0.95,
        risk_score=95,
        confidence=0.90,
        verdict="dangerous",
        shannon_entropy=4.5,
        features={},
        top_indicators=[
            MLFeatureContribution(
                feature_name="domain_entropy",
                feature_value="4.5",
                weight=8.5,
                description="High entropy",
            )
        ],
        summary="High phishing risk pattern.",
    )

    # 1. With ML weight = 0.10
    with patch.object(settings, "ENABLE_ML_CLASSIFICATION", True):
        with patch.object(settings, "ML_RISK_WEIGHT", 0.10):
            res_10 = evaluate_risk(findings=[], ml_result=mock_ml)
            assert "ml_classifier" in res_10.subscores
            assert res_10.subscores["ml_classifier"].score == 95

        # 2. With ML weight = 0.30 (higher influence)
        with patch.object(settings, "ML_RISK_WEIGHT", 0.30):
            res_30 = evaluate_risk(findings=[], ml_result=mock_ml)
            assert res_30.risk_score > res_10.risk_score

        # 3. With ML disabled
        with patch.object(settings, "ENABLE_ML_CLASSIFICATION", False):
            res_disabled = evaluate_risk(findings=[], ml_result=mock_ml)
            # When ML is disabled, ml_score contributes 0 to composite
            assert res_disabled.risk_score == 0


def test_benign_url_classification(mock_benign_prediction):
    """
    Test 6: Verify benign URLs produce 'info' severity finding and safe verdict.
    """
    session = local_session_factory()
    try:
        scan = Scan(
            input_url="https://legitimate-corp.com/about",
            normalized_url="https://legitimate-corp.com/about",
            status="queued",
            current_step=0,
            current_action="Queued",
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

        with patch.object(URLClassifier, "predict", return_value=mock_benign_prediction):
            completed_scan = execute_scan_pipeline_sync(scan_id=scan_id, resolve_network=False)

        assert completed_scan.status == "completed"

        ml_finding = (
            session.query(ScanFinding)
            .filter(ScanFinding.scan_id == scan_id, ScanFinding.category == "ml_classifier")
            .first()
        )
        assert ml_finding is not None
        assert ml_finding.severity == "info"
        assert ml_finding.evidence["predicted_label"] == "benign"
        assert ml_finding.evidence["phishing_probability"] < 0.5
    finally:
        session.close()
