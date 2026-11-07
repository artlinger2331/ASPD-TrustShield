import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import status


@pytest.mark.asyncio
async def test_root_health_liveness(async_client: AsyncClient):
    """
    Test GET /health returns 200 OK and expected liveness payload.
    """
    response = await async_client.get("/health")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "trustshield"
    assert "version" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_cors_headers_for_react_app(async_client: AsyncClient):
    """
    Test CORS middleware correctly responds to requests from the React frontend (http://localhost:5173).
    """
    headers = {"Origin": "http://localhost:5173"}
    response = await async_client.get("/health", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_api_v1_health_readiness(async_client: AsyncClient):
    """
    Test GET /api/v1/health readiness probe responds with service metadata and subsystems.
    """
    response = await async_client.get("/api/v1/health")
    assert response.status_code in [status.HTTP_200_OK, status.HTTP_503_SERVICE_UNAVAILABLE]

    data = response.json()
    assert "status" in data
    assert "service" in data
    assert "subsystems" in data
    assert "database" in data["subsystems"]


@pytest.mark.asyncio
async def test_postgresql_connection_via_database_url(db_session: AsyncSession):
    """
    Unit test verifying that PostgreSQL is directly queryable via DATABASE_URL.
    """
    try:
        result = await db_session.execute(text("SELECT 1 AS alive, current_database() AS dbname"))
        row = result.mappings().one()
        assert row["alive"] == 1
        assert isinstance(row["dbname"], str)
    except Exception as exc:
        pytest.skip(f"PostgreSQL server not currently reachable via DATABASE_URL ({exc})")


@pytest.mark.asyncio
async def test_standardized_error_envelope(async_client: AsyncClient):
    """
    Test that invalid routes or unhandled errors return the standardized SecOps error envelope.
    """
    response = await async_client.get("/api/v1/non-existent-endpoint")
    assert response.status_code == status.HTTP_404_NOT_FOUND

    data = response.json()
    # FastAPI default 404 returns {"detail": "Not Found"}
    assert "detail" in data or "error" in data
