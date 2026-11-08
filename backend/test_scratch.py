import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

import asyncio
from unittest.mock import patch, MagicMock
from app.api.v1.scans import create_scan
from app.schemas.scan import ScanCreate
from fastapi import BackgroundTasks
from app.db.session import local_session_factory, AsyncSessionFallback

async def main():
    print("Step 1: Init db")
    sess = local_session_factory()
    db = AsyncSessionFallback(sess)
    bg = BackgroundTasks()
    
    print("Step 2: Calling create_scan with mock dispatch")
    with patch("app.api.v1.scans.dispatch_scan") as mock_d:
        res = await create_scan(ScanCreate(url="https://direct-test.com/login"), bg, None, db)
        print("Step 3: create_scan done:", res.id, res.status)

    sess.close()
    print("Step 4: All done!")

if __name__ == "__main__":
    asyncio.run(main())
