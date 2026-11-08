import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from unittest.mock import patch
from app.api.v1.scans import create_scan, get_scan_status, get_scan_report
from app.schemas.scan import ScanCreate
from fastapi import BackgroundTasks
from app.db.session import local_session_factory, AsyncSessionFallback

def run_coro(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as e:
        return e.value

print("1. Starting...", flush=True)
sess = local_session_factory()
db = AsyncSessionFallback(sess)
bg = BackgroundTasks()

print("2. Calling create_scan...", flush=True)
with patch("app.api.v1.scans.dispatch_scan"):
    res = run_coro(create_scan(ScanCreate(url="https://direct-test.com/login"), bg, None, db))
    print("3. Created scan:", res.id, res.status, res.current_step, flush=True)
    stat = run_coro(get_scan_status(res.id, db))
    print("4. Status polled:", stat.status, stat.step, stat.current_action, flush=True)

sess.close()
print("5. All done!", flush=True)
