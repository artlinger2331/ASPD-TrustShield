"""
Celery Application Configuration for TrustShield SecOps.
Provides asynchronous worker queue management, task retries, and task result tracking.
Includes resilient fallback when Celery or Redis is not present in local environment.
"""

import os
import socket
from urllib.parse import urlparse

from app.core.config import settings

# ---------------------------------------------------------------------------
# CELERY IMPORT & RESILIENT FALLBACK
# ---------------------------------------------------------------------------

try:
    from celery import Celery
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False
    Celery = None


# ---------------------------------------------------------------------------
# REDIS AVAILABILITY DETECTION
# ---------------------------------------------------------------------------

def is_redis_available() -> bool:
    """
    Checks if Redis server is reachable and Celery library is installed.
    Returns False in offline local dev environments.
    """
    if not HAS_CELERY:
        return False

    try:
        parsed = urlparse(settings.REDIS_URL)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CELERY INSTANCE OR DUMMY SHIM
# ---------------------------------------------------------------------------

if HAS_CELERY:
    celery_app = Celery(
        "trustshield",
        broker=settings.REDIS_URL,
        backend=settings.REDIS_URL,
        include=[
            "app.tasks.scan_tasks",
            "app.tasks.maintenance",
        ],
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,                   # Acknowledge only after task completes
        worker_prefetch_multiplier=1,          # Prevent greedy prefetching on long scans
        task_soft_time_limit=90,               # 90s soft timeout
        task_time_limit=120,                   # 120s hard timeout
        result_expires=86400,                  # Retain task status for 24h
        beat_schedule={
            "reap-stale-scans-every-2-minutes": {
                "task": "app.tasks.maintenance.reap_stale_scans_task",
                "schedule": 120.0,
            },
        },
    )
else:
    class DummyConf:
        timezone = "UTC"
        task_acks_late = True

    class DummyCelery:
        """Fallback mock for environments without Celery installed."""
        def __init__(self, name="trustshield", **kwargs):
            self.main = name
            self.tasks = {}
            self.conf = DummyConf()

        def task(self, *args, **kwargs):
            def decorator(func):
                func_name = kwargs.get("name") or f"{func.__module__}.{func.__name__}"
                self.tasks[func_name] = func
                func.delay = lambda *a, **k: func(*a, **k)
                func.apply_async = lambda *a, **k: func(*a, **k)
                return func
            if len(args) == 1 and callable(args[0]):
                return decorator(args[0])
            return decorator

    celery_app = DummyCelery("trustshield")
