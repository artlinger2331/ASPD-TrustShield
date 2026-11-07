"""
Live Security Notifications & Server-Sent Events (SSE) Stream.
Provides real-time event streaming for scans, alerts, and community reports.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncGenerator
from fastapi import APIRouter, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import settings

router = APIRouter(prefix="/notifications", tags=["Live Notifications"])


async def event_generator(request: Request) -> AsyncGenerator[str, None]:
    """
    Yields real-time security events to connected clients.
    """
    # Send initial connection event
    initial_event = {
        "event": "connected",
        "data": {
            "status": "active",
            "service": "TrustShield Realtime SecOps Stream",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
    yield f"data: {json.dumps(initial_event)}\n\n"

    try:
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            await asyncio.sleep(15.0)

            # Heartbeat ping
            heartbeat = {
                "event": "ping",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            yield f"data: {json.dumps(heartbeat)}\n\n"
    except asyncio.CancelledError:
        pass


@router.get(
    "/stream",
    summary="Subscribe to live SSE security telemetry and alerts stream",
)
async def notification_stream(request: Request):
    """
    Subscribes the browser client to Server-Sent Events for real-time alerts.
    """
    return StreamingResponse(
        event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

