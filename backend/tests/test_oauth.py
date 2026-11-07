import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.config import settings


@pytest.mark.asyncio
async def test_google_oauth_redirect_simulation(async_client: AsyncClient):
    """
    Test GET /api/v1/auth/oauth/google initiates flow and redirects.
    """
    response = await async_client.get("/api/v1/auth/oauth/google", follow_redirects=False)
    assert response.status_code in (302, 307)
    location = response.headers.get("location")
    assert location is not None
    assert "/auth/provider-consent?provider=google" in location or "accounts.google.com" in location


@pytest.mark.asyncio
async def test_github_oauth_redirect_simulation(async_client: AsyncClient):
    """
    Test GET /api/v1/auth/oauth/github initiates flow and redirects.
    """
    response = await async_client.get("/api/v1/auth/oauth/github", follow_redirects=False)
    assert response.status_code in (302, 307)
    location = response.headers.get("location")
    assert location is not None
    assert "/auth/provider-consent?provider=github" in location or "github.com" in location


@pytest.mark.asyncio
async def test_google_oauth_callback_creates_session(async_client: AsyncClient):
    """
    Test GET /api/v1/auth/oauth/google/callback with simulated code returns tokens and redirects to frontend.
    """
    response = await async_client.get(
        "/api/v1/auth/oauth/google/callback",
        params={
            "code": "dev_google_mock_code",
            "email": "test.google.user@example.com",
            "name": "Test Google User",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 307)
    location = response.headers.get("location")
    assert location is not None
    assert "/auth/callback" in location
    assert "token=" in location
    assert "refresh_token=" in location
    assert "provider=google" in location

    # Verify cookies
    cookies = response.cookies
    assert "ts_access_token" in cookies
    assert "ts_refresh_token" in cookies


@pytest.mark.asyncio
async def test_github_oauth_callback_creates_session(async_client: AsyncClient):
    """
    Test GET /api/v1/auth/oauth/github/callback with simulated code returns tokens and redirects to frontend.
    """
    response = await async_client.get(
        "/api/v1/auth/oauth/github/callback",
        params={
            "code": "dev_github_mock_code",
            "email": "test.github.user@example.com",
            "name": "Test GitHub Developer",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 307)
    location = response.headers.get("location")
    assert location is not None
    assert "/auth/callback" in location
    assert "token=" in location
    assert "refresh_token=" in location
    assert "provider=github" in location

    # Verify cookies
    cookies = response.cookies
    assert "ts_access_token" in cookies
    assert "ts_refresh_token" in cookies
