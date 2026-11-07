"""
Maintenance Tasks & Watchdog for Stale / Zombie Scans.
"""

from datetime import datetime, timezone, timedelta
import logging
from sqlalchemy import select, or_

from app.core.celery_app import celery_app
from app.db.session import local_session_factory, sync_engine
from app.models.scan import Scan

logger = logging.getLogger("trustshield.maintenance")


def reap_stale_scans(stale_minutes: int = 5) -> int:
    """
    Finds and marks scans stuck in 'running' or 'queued' past the timeout threshold.
    Returns the number of reaped scans.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_minutes)
    reaped_count = 0

    with local_session_factory() as session:
        try:
            query = select(Scan).where(
                or_(Scan.status == "running", Scan.status == "queued"),
                Scan.created_at <= cutoff,
            )
            stale_scans = session.execute(query).scalars().all()

            for scan in stale_scans:
                scan.status = "timeout"
                scan.error_message = f"Scan timed out after exceeding {stale_minutes} minutes."
                scan.completed_at = datetime.now(timezone.utc)
                reaped_count += 1
                logger.warning(f"Watchdog reaped zombie scan: {scan.id} (status was {scan.status})")

            if reaped_count > 0:
                session.commit()
        except Exception as exc:
            logger.error(f"Error during stale scan reaper: {exc}", exc_info=True)
            session.rollback()

    return reaped_count


@celery_app.task(name="app.tasks.maintenance.reap_stale_scans_task")
def reap_stale_scans_task() -> dict:
    """
    Celery Beat task running periodically to clean up orphaned scan executions.
    """
    reaped = reap_stale_scans(stale_minutes=5)
    return {"status": "ok", "reaped_count": reaped}

