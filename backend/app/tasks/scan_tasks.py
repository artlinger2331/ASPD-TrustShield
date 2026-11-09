"""
Celery Scan Tasks & Execution Dispatcher.
Provides distributed asynchronous scanning with automatic in-process fallback.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import BackgroundTasks

try:
    from celery.exceptions import SoftTimeLimitExceeded
except ImportError:
    class SoftTimeLimitExceeded(Exception):
        pass

from app.core.celery_app import celery_app, is_redis_available
from app.services.scan_orchestrator import execute_scan_pipeline_sync
from app.services.risk_engine import evaluate_risk
from app.db.session import local_session_factory
from app.models.scan import Scan
from app.models.scan_finding import ScanFinding
from app.models.certificate import Certificate
from app.models.threat_intel import ThreatIntelResult

logger = logging.getLogger("trustshield.tasks")


@celery_app.task(
    bind=True,
    max_retries=2,
    default_retry_delay=5,
    name="app.tasks.scan_tasks.execute_scan_task",
)
def execute_scan_task(self, scan_id_str: str) -> dict:
    """
    Celery task that executes the complete passive scanning pipeline.
    Handles soft timeout and preserves partial findings.
    """
    try:
        scan_uuid = uuid.UUID(scan_id_str)
        report = execute_scan_pipeline_sync(scan_uuid)
        return {
            "status": "completed" if report and report.status == "completed" else "failed",
            "scan_id": scan_id_str,
            "verdict": report.verdict if report else "unknown",
            "risk_score": report.risk_score if report else 0,
        }
    except SoftTimeLimitExceeded:
        logger.error(f"Scan {scan_id_str} timed out (SoftTimeLimitExceeded). Preserving partial findings.")
        session = local_session_factory()
        try:
            scan_uuid = uuid.UUID(scan_id_str)
            scan = session.query(Scan).filter(Scan.id == scan_uuid).first()
            if scan:
                scan.status = "failed"
                scan.error_message = "Scan execution timed out after 90 seconds. Partial findings preserved."
                scan.current_action = "Scan timed out"
                scan.completed_at = datetime.now(timezone.utc)
                findings = session.query(ScanFinding).filter(ScanFinding.scan_id == scan_uuid).all()
                cert = session.query(Certificate).filter(Certificate.scan_id == scan_uuid).first()
                threat_results = session.query(ThreatIntelResult).filter(ThreatIntelResult.scan_id == scan_uuid).all()
                if findings or cert or threat_results:
                    evaluation = evaluate_risk(
                        findings=findings,
                        certificate=cert,
                        threat_intel_results=threat_results,
                        ml_result=None,
                        domain=getattr(scan, "normalized_url", None) or "unknown",
                    )
                    scan.verdict = evaluation.verdict
                    scan.risk_score = evaluation.risk_score
                    scan.confidence = evaluation.confidence
                    scan.summary = "Scan timed out. Preliminary risk assessment generated from partial findings."
                    scan.recommendation = evaluation.recommendation
                session.commit()
        except Exception as e:
            logger.error(f"Error handling timeout for scan {scan_id_str}: {e}")
            session.rollback()
        finally:
            session.close()
        return {
            "status": "failed",
            "scan_id": scan_id_str,
            "error": "Scan execution timed out after 90 seconds",
        }
    except Exception as exc:
        logger.error(f"Error executing scan {scan_id_str} in Celery task: {exc}", exc_info=True)
        # Retry once on unexpected infrastructure/network failure if retries left
        if getattr(self.request, "retries", 0) < self.max_retries:
            raise self.retry(exc=exc)
        return {
            "status": "failed",
            "scan_id": scan_id_str,
            "error": str(exc),
        }


def dispatch_scan(
    scan_id: uuid.UUID,
    background_tasks: Optional[BackgroundTasks] = None,
) -> str:
    """
    Intelligently routes scan execution to Celery/Redis if online,
    or falls back to FastAPI BackgroundTasks for local developer resilience.
    Returns the dispatch mode: 'celery' or 'in_process'.
    """
    scan_id_str = str(scan_id)

    if is_redis_available():
        try:
            execute_scan_task.delay(scan_id_str)
            logger.info(f"Dispatched scan {scan_id} to Celery queue via Redis.")
            return "celery"
        except Exception as exc:
            logger.warning(
                f"Failed to enqueue scan {scan_id} in Celery ({exc}). Falling back to in-process."
            )

    # In-process fallback
    if background_tasks is not None:
        background_tasks.add_task(execute_scan_pipeline_sync, scan_id=scan_id)
        logger.info(f"Dispatched scan {scan_id} to in-process FastAPI BackgroundTasks.")
        return "in_process"
    else:
        # Direct synchronous execution if background_tasks is omitted
        execute_scan_pipeline_sync(scan_id=scan_id)
        return "sync_direct"

