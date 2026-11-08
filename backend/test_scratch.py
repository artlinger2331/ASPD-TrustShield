import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

import asyncio
from unittest.mock import patch, MagicMock
from app.api.v1.scans import create_scan, get_scan_status, get_scan_report
from app.schemas.scan import ScanCreate
from fastapi import BackgroundTasks
from app.db.session import local_session_factory, AsyncSessionFallback
from app.services.scan_orchestrator import execute_scan_pipeline_sync

async def main():
    print("Testing create_scan...")
    db = AsyncSessionFallback(local_session_factory())
    bg = BackgroundTasks()
    
    with patch("app.api.v1.scans.dispatch_scan") as mock_disp:
        res = await create_scan(ScanCreate(url="https://direct-test.com/portal"), bg, None, db)
        print("Scan created successfully:", res.id, "status:", res.status, "step:", res.current_step)
        
        status_res = await get_scan_status(res.id, db)
        print("Status polled:", status_res.status, "step:", status_res.step, "action:", status_res.current_action)
        
        print("Executing pipeline...")
        scan = execute_scan_pipeline_sync(res.id, resolve_network=False, mock_html="<html><body>Hello</body></html>")
        print("Pipeline finished:", scan.status, "score:", scan.risk_score, "step:", scan.current_step)
        
        status_completed = await get_scan_status(res.id, db)
        print("Status completed polled:", status_completed.status, "step:", status_completed.step, "score:", status_completed.risk_score)
        
        report = await get_scan_report(res.id, db)
        print("Report retrieved:", report.status, "findings count:", len(report.findings))

if __name__ == "__main__":
    asyncio.run(main())
