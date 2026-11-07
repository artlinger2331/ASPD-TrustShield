import time
from typing import Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis

from app.core.config import settings
from app.db.session import get_db

router = APIRouter(prefix="", tags=["Health"])


@router.get(
    "/health",
    summary="Comprehensive Subsystem Readiness Probe",
    status_code=status.HTTP_200_OK,
)
async def readiness_probe(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Subsystem readiness probe for `/api/v1/health`.
    Actively checks PostgreSQL connection (executing `SELECT 1`)
    and Redis connection status, returning component latencies.
    """
    subsystems: Dict[str, Any] = {}
    is_healthy = True

    # 1. Probe PostgreSQL Database
    db_start = time.perf_counter()
    try:
        result = await db.execute(text("SELECT 1"))
        scalar_val = result.scalar()
        db_latency = round((time.perf_counter() - db_start) * 1000, 2)
        if scalar_val == 1:
            subsystems["database"] = {
                "status": "connected",
                "engine": "postgresql",
                "latency_ms": db_latency,
            }
        else:
            is_healthy = False
            subsystems["database"] = {
                "status": "unexpected_result",
                "latency_ms": db_latency,
            }
    except Exception as exc:
        is_healthy = False
        db_latency = round((time.perf_counter() - db_start) * 1000, 2)
        subsystems["database"] = {
            "status": "error",
            "latency_ms": db_latency,
            "error": str(exc),
        }

    # 2. Probe Redis (optional / non-blocking check)
    redis_start = time.perf_counter()
    try:
        r = aioredis.from_url(settings.REDIS_URL, socket_timeout=1.5)
        await r.ping()
        await r.aclose()
        redis_latency = round((time.perf_counter() - redis_start) * 1000, 2)
        subsystems["redis"] = {
            "status": "connected",
            "latency_ms": redis_latency,
        }
    except Exception as exc:
        redis_latency = round((time.perf_counter() - redis_start) * 1000, 2)
        subsystems["redis"] = {
            "status": "unreachable",
            "latency_ms": redis_latency,
            "note": "Celery job queue or threat cache may be offline",
        }

    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": settings.PROJECT_NAME.lower(),
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subsystems": subsystems,
    }

