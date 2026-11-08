import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app

async def run():
    print("Setting up transport...")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        print("Sending POST request to /api/v1/scans/validate...")
        resp = await ac.post(
            "/api/v1/scans/validate",
            json={"url": "https://docs.github.com/en/actions?query=workflow#summary", "resolve_dns": False},
        )
        print("Status:", resp.status_code)
        print("Data:", resp.json())

if __name__ == "__main__":
    asyncio.run(run())
