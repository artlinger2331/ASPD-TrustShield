import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from datetime import datetime, timezone, timedelta
from sqlalchemy import select, desc
from app.models.scan import Scan
from app.db.session import local_session_factory, AsyncSessionFallback
import asyncio

async def test():
    print("Connecting...")
    sess = local_session_factory()
    db = AsyncSessionFallback(sess)
    five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    stmt = (
        select(Scan)
        .where(
            Scan.normalized_url == "https://direct-test.com/portal",
            Scan.status.in_(["queued", "running"]),
            Scan.created_at >= five_minutes_ago,
        )
        .order_by(desc(Scan.created_at))
    )
    print("Executing query...")
    res = await db.execute(stmt)
    print("Query executed, fetching first...")
    scan = res.scalars().first()
    print("Scan:", scan)

if __name__ == "__main__":
    asyncio.run(test())
