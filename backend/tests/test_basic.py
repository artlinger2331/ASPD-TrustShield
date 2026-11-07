import pytest
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import root_liveness

@pytest.mark.asyncio
async def test_root_liveness():
    res = await root_liveness()
    assert res["status"] == "ok"
    assert res["service"] == "trustshield"
