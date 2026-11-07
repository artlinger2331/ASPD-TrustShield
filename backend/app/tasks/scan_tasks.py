"""
Celery Scan Tasks & Execution Dispatcher.
Provides distributed asynchronous scanning with automatic in-process fallback.
"""

import uuid
import logging
from typing import Optional
from fastapi import BackgroundTasks

from app.core.celery_app import celery_app, is_redis_available
from app.services.scan_orchestrator import execute_scan_pipeline_sync

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
    """
    try:
        scan_uuid = uuid.UUID(scan_id_str)
        report = execute_scan_pipeline_sync(scan_uuid)
        return {
            "status": "completed",
            "scan_id": scan_id_str,
            "verdict": report.verdict if report else "unknown",
            "risk_score": report.risk_score if report else 0,
        }
    except Exception as exc:
        logger.error(f"Error executing scan {scan_id_str} in Celery task: {exc}", exc_info=True)
        # Retry once on unexpected infrastructure/network failure
        raise self.retry(exc=exc)


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
