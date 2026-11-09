import os
import socket
from pathlib import Path
from typing import AsyncGenerator, Generator, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.core.config import settings
from app.db.base import Base

# Determine if PostgreSQL host is reachable
_use_sqlite_fallback = False

def _check_postgres_reachable() -> bool:
    url = settings.DATABASE_URL
    if "sqlite" in url:
        return False
    try:
        # Extract host and port
        host = "127.0.0.1"
        port = 5432
        if "@" in url:
            host_part = url.split("@")[1].split("/")[0]
            if ":" in host_part:
                host, port_str = host_part.split(":")
                port = int(port_str)
            else:
                host = host_part

        if host in ("db", "postgres"):
            # In local dev outside Docker, avoid Windows DNS lookup hang on docker service name
            host = "127.0.0.1"

        with socket.create_connection((host, port), timeout=0.2):
            return True
    except Exception:
        return False

_use_sqlite_fallback = not _check_postgres_reachable()

# 1. Primary PostgreSQL Async Engine
if not _use_sqlite_fallback:
    async_engine = create_async_engine(
        settings.async_database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        connect_args={"timeout": 3.0},
    )
    async_session_factory = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
else:
    async_engine = None
    async_session_factory = None

# 2. Local SQLite Engine for Dev Resilience
db_dir = Path(__file__).resolve().parent.parent.parent
sqlite_path = db_dir / "trustshield_dev.db"
local_sync_engine = create_engine(
    f"sqlite:///{sqlite_path}",
    echo=False,
    connect_args={"check_same_thread": False},
)
sync_engine = local_sync_engine
local_session_factory = sessionmaker(
    bind=local_sync_engine,
    class_=Session,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# Auto-initialize SQLite schema if in fallback mode
_sqlite_initialized = False

def init_sqlite_db():
    global _sqlite_initialized
    if _sqlite_initialized or not _use_sqlite_fallback:
        return
    _sqlite_initialized = True
    try:
        from app.db.base import Base
        import app.models  # Load all models
        Base.metadata.create_all(local_sync_engine)

        with local_sync_engine.connect() as conn:
            res = conn.exec_driver_sql("PRAGMA table_info(scans)").fetchall()
            cols = [r[1] for r in res]
            if "explanation" not in cols and "id" in cols:
                conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN explanation JSON")
                conn.commit()
    except Exception:
        pass

if _use_sqlite_fallback:
    init_sqlite_db()


class AsyncSessionFallback:
    """
    Transparent async wrapper around a synchronous SQLAlchemy Session.
    Ensures seamless local development persistence when PostgreSQL/Docker is offline.
    """
    def __init__(self, sync_session: Session):
        self._s = sync_session

    async def execute(self, statement, *args, **kwargs):
        return self._s.execute(statement, *args, **kwargs)

    def add(self, instance):
        self._s.add(instance)

    async def commit(self):
        self._s.commit()

    async def rollback(self):
        self._s.rollback()

    async def refresh(self, instance, *args, **kwargs):
        self._s.refresh(instance, *args, **kwargs)

    async def close(self):
        self._s.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._s.rollback()
        self._s.close()


# 3. FastAPI Dependency
async def get_db() -> AsyncGenerator[Any, None]:
    """
    FastAPI dependency that yields an active database session.
    Prioritizes PostgreSQL async engine; seamlessly falls back to persistent
    SQLite store if PostgreSQL / Docker Compose is not reachable locally.
    """
    if _use_sqlite_fallback or async_session_factory is None:
        session = local_session_factory()
        fallback = AsyncSessionFallback(session)
        try:
            yield fallback
        except Exception:
            await fallback.rollback()
            raise
        finally:
            await fallback.close()
        return

    try:
        async with async_session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    except Exception:
        # Fallback to local SQLite if PostgreSQL fails mid-operation
        session = local_session_factory()
        fallback = AsyncSessionFallback(session)
        try:
            yield fallback
        except Exception:
            await fallback.rollback()
            raise
        finally:
            await fallback.close()


def get_sync_db() -> Generator[Session, None, None]:
    """
    Sync context generator for Celery tasks or offline scripts.
    """
    session = local_session_factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
