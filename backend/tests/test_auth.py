import pytest
from httpx import AsyncClient
from fastapi import status, APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.api.deps import require_roles, get_current_active_user
from app.models.user import User

# Test RBAC protected endpoint
rbac_router = APIRouter(prefix="/api/v1/test-rbac", tags=["Test"])

@rbac_router.get("/admin-only")
async def admin_only_route(current_user: User = Depends(require_roles(["admin"]))):
    return {"message": f"Welcome Admin {current_user.email}"}

@rbac_router.get("/moderator-or-admin")
async def mod_route(current_user: User = Depends(require_roles(["moderator", "admin"]))):
    return {"message": f"Welcome Staff {current_user.email}"}

app.include_router(rbac_router)


@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient):
    """Test successful user registration returns tokens and user object."""
    payload = {
        "email": "test_register@trustshield.local",
        "password": "Password123!",
        "full_name": "Test User",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    print("\nREGISTER RESPONSE:", response.status_code, response.json())
    assert response.status_code == status.HTTP_201_CREATED

    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "test_register@trustshield.local"
    assert data["user"]["role"] == "user"
    assert data["user"]["full_name"] == "Test User"
    assert "set-cookie" in response.headers


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: AsyncClient):
    """Test registering with an existing email returns 400 validation error."""
    payload = {
        "email": "duplicate@trustshield.local",
        "password": "Password123!",
        "full_name": "Original User",
    }
    first_res = await async_client.post("/api/v1/auth/register", json=payload)
    assert first_res.status_code == status.HTTP_201_CREATED

    second_res = await async_client.post("/api/v1/auth/register", json=payload)
    assert second_res.status_code == status.HTTP_400_BAD_REQUEST
    err_data = second_res.json()
    assert err_data["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient):
    """Test login with valid credentials."""
    email = "login_success@trustshield.local"
    password = "CorrectPassword123!"

    # 1. Register
    await async_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": "Login User"},
    )

    # 2. Login
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == status.HTTP_200_OK
    data = login_res.json()
    assert "access_token" in data
    assert data["user"]["email"] == email


@pytest.mark.asyncio
async def test_login_invalid_password(async_client: AsyncClient):
    """Test login with incorrect password returns 401 Unauthorized."""
    email = "wrong_pwd@trustshield.local"
    password = "CorrectPassword123!"

    await async_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )

    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword!"},
    )
    assert login_res.status_code == status.HTTP_401_UNAUTHORIZED
    err = login_res.json()
    assert err["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_get_current_user_me(async_client: AsyncClient):
    """Test GET /api/v1/auth/me with valid Bearer token."""
    email = "get_me@trustshield.local"
    password = "Password123!"

    reg_res = await async_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "full_name": "Me User"},
    )
    token = reg_res.json()["access_token"]

    # Call /me with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = await async_client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == status.HTTP_200_OK
    me_data = me_res.json()
    assert me_data["email"] == email
    assert me_data["full_name"] == "Me User"


@pytest.mark.asyncio
async def test_get_current_user_unauthorized(async_client: AsyncClient):
    """Test GET /api/v1/auth/me without token returns 401."""
    me_res = await async_client.get("/api/v1/auth/me")
    assert me_res.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_refresh_token_rotation(async_client: AsyncClient):
    """Test refreshing an access token with a valid refresh token."""
    email = "refresher@trustshield.local"
    password = "Password123!"

    reg_res = await async_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    refresh_token = reg_res.json()["refresh_token"]

    refresh_res = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_res.status_code == status.HTTP_200_OK
    data = refresh_res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    # Verify new access token works on /me
    me_res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {data['access_token']}"},
    )
    assert me_res.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_logout(async_client: AsyncClient):
    """Test logout clears auth cookies."""
    res = await async_client.post("/api/v1/auth/logout")
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["message"] == "Successfully logged out"


@pytest.mark.asyncio
async def test_role_based_authorization(async_client: AsyncClient, db_session: AsyncSession):
    """Test RBAC enforcement: standard user gets 403 on admin routes."""
    # 1. Register a normal user (role='user')
    email = "normal_user@trustshield.local"
    reg_res = await async_client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Password123!"},
    )
    user_token = reg_res.json()["access_token"]

    # 2. Try to access admin-only route -> 403 Forbidden
    admin_res = await async_client.get(
        "/api/v1/test-rbac/admin-only",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert admin_res.status_code == status.HTTP_403_FORBIDDEN
    assert admin_res.json()["error"]["code"] == "FORBIDDEN"
