print("1. Program starting...", flush=True)
import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

print("2. Importing scans...", flush=True)
from app.api.v1.scans import create_scan
print("3. Importing ScanCreate...", flush=True)
from app.schemas.scan import ScanCreate
print("4. Importing session...", flush=True)
from app.db.session import local_session_factory, AsyncSessionFallback
print("5. Importing patch...", flush=True)
from unittest.mock import patch
print("6. Importing BackgroundTasks...", flush=True)
from fastapi import BackgroundTasks
print("7. Importing asyncio...", flush=True)
import asyncio

async def main():
    print("8. Entering main...", flush=True)
    sess = local_session_factory()
    db = AsyncSessionFallback(sess)
    bg = BackgroundTasks()
    print("9. Calling create_scan...", flush=True)
    with patch("app.api.v1.scans.dispatch_scan"):
        res = await create_scan(ScanCreate(url="https://direct-test.com/login"), bg, None, db)
        print(f"10. Created: {res.id}", flush=True)
    sess.close()
    print("11. Done!", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
