import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

import asyncio
from unittest.mock import patch
from app.api.v1.scans import create_scan, get_scan_status, get_scan_report
from app.schemas.scan import ScanCreate
from fastapi import BackgroundTasks
from app.db.session import local_session_factory, AsyncSessionFallback

async def run():
    db = AsyncSessionFallback(local_session_factory())
    bg = BackgroundTasks()
    with patch("app.api.v1.scans.dispatch_scan") as mock_d:
        res = await create_scan(ScanCreate(url="https://direct-test.com/login"), bg, None, db)
        print("CREATED:", res.id, res.status, res.current_step)
        stat = await get_scan_status(res.id, db)
        print("STATUS:", stat.status, stat.step, stat.current_action)

if __name__ == "__main__":
    asyncio.run(run())
