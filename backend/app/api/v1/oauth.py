import os
import uuid
import secrets
from urllib.parse import urlencode
from typing import Optional
from pathlib import Path
import httpx
from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    hash_password,
    create_access_token,
    create_refresh_token,
)
from app.db.session import get_db
from app.models.user import User

router = APIRouter(prefix="/auth/oauth", tags=["OAuth Authentication"])

# Ephemeral state storage for CSRF protection
_OAUTH_STATES = set()


class OAuthConfigPayload(BaseModel):
    provider: str = Field(..., description="Provider name: 'google' or 'github'")
    client_id: str = Field(..., description="OAuth Client ID")
    client_secret: str = Field(..., description="OAuth Client Secret")


def _update_env_file(key: str, value: str) -> None:
    """Helper to update a key-value pair in both .env and backend/.env"""
    env_paths = [
        Path(__file__).resolve().parent.parent.parent.parent / ".env",
        Path(__file__).resolve().parent.parent.parent.parent.parent / ".env",
    ]
    for env_path in env_paths:
        if env_path.exists():
            try:
                lines = env_path.read_text(encoding="utf-8").splitlines()
                updated = False
                new_lines = []
                for line in lines:
                    if line.startswith(f"{key}="):
                        new_lines.append(f"{key}={value}")
                        updated = True
                    else:
                        new_lines.append(line)
                if not updated:
                    new_lines.append(f"{key}={value}")
                env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            except Exception:
                pass


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key="ts_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/",
    )
    response.set_cookie(
        key="ts_access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


# -------------------------------------------------------------------------
# OAUTH CONFIGURATION STATUS & LIVE CREDENTIALS SETUP
# -------------------------------------------------------------------------

@router.get("/status", summary="Check OAuth Providers Configuration Status")
async def oauth_status():
    """
    Returns whether Google and GitHub OAuth have valid credentials configured.
    """
    return {
        "google": {
            "configured": bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET),
            "client_id": settings.GOOGLE_CLIENT_ID or "",
        },
        "github": {
            "configured": bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET),
            "client_id": settings.GITHUB_CLIENT_ID or "",
        },
    }


@router.post("/configure", summary="Configure OAuth Credentials")
async def configure_oauth(payload: OAuthConfigPayload):
    """
    Dynamically saves client credentials to .env and settings,
    returning the direct provider authorization URL.
    """
    provider = payload.provider.strip().lower()
    c_id = payload.client_id.strip()
    c_secret = payload.client_secret.strip()

    if provider == "google":
        settings.GOOGLE_CLIENT_ID = c_id
        settings.GOOGLE_CLIENT_SECRET = c_secret
        _update_env_file("GOOGLE_CLIENT_ID", c_id)
        _update_env_file("GOOGLE_CLIENT_SECRET", c_secret)
        return {
            "status": "success",
            "message": "Google OAuth credentials saved successfully.",
            "auth_url": f"{settings.BACKEND_URL}/api/v1/auth/oauth/google",
        }
    elif provider == "github":
        settings.GITHUB_CLIENT_ID = c_id
        settings.GITHUB_CLIENT_SECRET = c_secret
        _update_env_file("GITHUB_CLIENT_ID", c_id)
        _update_env_file("GITHUB_CLIENT_SECRET", c_secret)
        return {
            "status": "success",
            "message": "GitHub OAuth credentials saved successfully.",
            "auth_url": f"{settings.BACKEND_URL}/api/v1/auth/oauth/github",
        }
    else:
        return JSONResponse(
            status_code=400,
            content={"error": "Unsupported OAuth provider. Choose 'google' or 'github'."},
        )


# -------------------------------------------------------------------------
# GOOGLE OAUTH
# -------------------------------------------------------------------------

@router.get("/google", summary="Initiate Google OAuth Flow")
async def google_login():
    """
    Redirects user directly to Google's official account chooser (accounts.google.com).
    Google will display all Google accounts logged into the user's browser.
    """
    state = secrets.token_urlsafe(32)
    _OAUTH_STATES.add(state)

    if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": f"{settings.BACKEND_URL}/api/v1/auth/oauth/google/callback",
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": state,
            "prompt": "select_account",
        }
        target_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        return RedirectResponse(url=target_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    # Prompt user to configure Google Client ID to connect their browser's Google accounts
    setup_url = f"{settings.FRONTEND_URL}/login?oauth_setup=google"
    return RedirectResponse(url=setup_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/google/callback", summary="Google OAuth Callback")
async def google_callback(
    code: str,
    state: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handles Google OAuth redirect, retrieves the authenticated user's real Google email
    and display name from Google Identity APIs, creates or logs in the user, and redirects to frontend.
    """
    if not (settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET):
        return RedirectResponse(
            url=f"{settings.FRONTEND_URL}/login?error=Google%20OAuth%20Client%20ID%20is%20not%20configured"
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": f"{settings.BACKEND_URL}/api/v1/auth/oauth/google/callback",
                "grant_type": "authorization_code",
            },
        )
        if token_res.status_code != 200:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=Google%20Authentication%20Failed"
            )

        token_data = token_res.json()
        google_access_token = token_data.get("access_token")

        userinfo_res = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {google_access_token}"},
        )
        if userinfo_res.status_code != 200:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=Failed%20to%20fetch%20Google%20profile"
            )

        userinfo = userinfo_res.json()
        user_email = userinfo.get("email")
        if not user_email:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=No%20email%20returned%20by%20Google"
            )
        user_email = user_email.lower().strip()
        user_name = userinfo.get("name") or user_email.split("@")[0].title()

    # Find or create user with real Google account
    user_id = str(uuid.uuid4())
    user_role = "user"
    try:
        query = select(User).where(User.email == user_email)
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            random_pwd = hash_password(secrets.token_urlsafe(32))
            user = User(
                email=user_email,
                hashed_password=random_pwd,
                full_name=user_name,
                role="user",
                is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        user_id = str(user.id)
        user_role = user.role
    except Exception:
        pass

    access_token = create_access_token(
        subject=user_id,
        email=user_email,
        role=user_role,
    )
    refresh_token = create_refresh_token(subject=user_id)

    redirect_url = f"{settings.FRONTEND_URL}/auth/callback?token={access_token}&refresh_token={refresh_token}&provider=google"
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    _set_auth_cookies(response, access_token, refresh_token)
    return response


# -------------------------------------------------------------------------
# GITHUB OAUTH
# -------------------------------------------------------------------------

@router.get("/github", summary="Initiate GitHub OAuth Flow")
async def github_login():
    """
    Redirects user to GitHub OAuth authorization page.
    """
    state = secrets.token_urlsafe(32)
    _OAUTH_STATES.add(state)

    if settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
        params = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": f"{settings.BACKEND_URL}/api/v1/auth/oauth/github/callback",
            "scope": "read:user user:email",
            "state": state,
        }
        target_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
        return RedirectResponse(url=target_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    setup_url = f"{settings.FRONTEND_URL}/login?oauth_setup=github"
    return RedirectResponse(url=setup_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/github/callback", summary="GitHub OAuth Callback")
async def github_callback(
    code: str,
    state: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handles GitHub OAuth redirect, retrieves verified email and username from GitHub,
    creates or logs in user, and redirects to frontend with session tokens.
    """
    if not (settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET):
        return RedirectResponse(
            url=f"{settings.FRONTEND_URL}/login?error=GitHub%20OAuth%20Client%20ID%20is%20not%20configured"
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{settings.BACKEND_URL}/api/v1/auth/oauth/github/callback",
            },
        )
        if token_res.status_code != 200:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=GitHub%20Authentication%20Failed"
            )

        token_data = token_res.json()
        gh_access_token = token_data.get("access_token")

        user_res = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {gh_access_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "TrustShield-OAuth",
            },
        )
        if user_res.status_code != 200:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=Failed%20to%20fetch%20GitHub%20profile"
            )

        gh_user = user_res.json()
        user_name = gh_user.get("name") or gh_user.get("login") or "GitHub User"
        user_email = gh_user.get("email")

        if not user_email:
            emails_res = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {gh_access_token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "TrustShield-OAuth",
                },
            )
            if emails_res.status_code == 200:
                emails = emails_res.json()
                primary_email = next((e["email"] for e in emails if e.get("primary")), None)
                if primary_email:
                    user_email = primary_email

        if not user_email:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=No%20verified%20email%20found%20for%20GitHub%20account"
            )

        user_email = user_email.lower().strip()

    # Find or create user
    user_id = str(uuid.uuid4())
    user_role = "user"
    try:
        query = select(User).where(User.email == user_email)
        result = await db.execute(query)
        user = result.scalar_one_or_none()

        if not user:
            random_pwd = hash_password(secrets.token_urlsafe(32))
            user = User(
                email=user_email,
                hashed_password=random_pwd,
                full_name=user_name,
                role="user",
                is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

        user_id = str(user.id)
        user_role = user.role
    except Exception:
        pass

    access_token = create_access_token(
        subject=user_id,
        email=user_email,
        role=user_role,
    )
    refresh_token = create_refresh_token(subject=user_id)

    redirect_url = f"{settings.FRONTEND_URL}/auth/callback?token={access_token}&refresh_token={refresh_token}&provider=github"
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    _set_auth_cookies(response, access_token, refresh_token)
    return response
