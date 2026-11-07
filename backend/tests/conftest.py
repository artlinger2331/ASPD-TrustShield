import sys
from pathlib import Path
from typing import AsyncGenerator

# Ensure 'backend' directory is in Python path for testing
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.orm import Session

from app.main import app
from app.models import Base
from app.db.session import (
    get_db,
    local_sync_engine,
    local_session_factory,
    AsyncSessionFallback,
)
from app.core.rate_limit import clear_rate_limit


@pytest_asyncio.fixture(autouse=True)
async def init_test_database():
    """
    Initialize schema tables and reset rate limits once per test.
    """
    clear_rate_limit()
    Base.metadata.create_all(local_sync_engine)
    yield


async def override_get_db() -> AsyncGenerator[AsyncSessionFallback, None]:
    sync_sess = local_session_factory()
    fallback = AsyncSessionFallback(sync_sess)
    try:
        yield fallback
    except Exception:
        await fallback.rollback()
        raise
    finally:
        await fallback.close()


app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """
    HTTP client configured for async API testing against the FastAPI application.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSessionFallback, None]:
    """
    Direct database session for unit testing database operations.
    """
    sync_sess = local_session_factory()
    fallback = AsyncSessionFallback(sync_sess)
    try:
        yield fallback
    except Exception:
        await fallback.rollback()
        raise
    finally:
        await fallback.close()
