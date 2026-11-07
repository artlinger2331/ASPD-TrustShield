from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.core.rate_limit import check_rate_limit
from app.core.exceptions import (
    ValidationException,
    UnauthorizedException,
    ForbiddenException,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    MessageResponse,
)
from app.schemas.user import UserResponse
from app.api.deps import get_current_active_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """
    Sets secure HttpOnly cookies for SPA session resilience against XSS.
    """
    # Refresh token cookie (strict security)
    response.set_cookie(
        key="ts_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Set to True in HTTPS production
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/",
    )
    # Access token cookie
    response.set_cookie(
        key="ts_access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New User",
)
async def register(
    request: Request,
    response: Response,
    payload: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Register a new user account with secure bcrypt hashing and return authentication tokens.
    """
    await check_rate_limit(request, key_prefix="register", max_requests=5, window_seconds=60)

    clean_email = payload.email.strip().lower()

    # Check if email is already registered
    existing_user_query = select(User).where(User.email == clean_email)
    existing_user_result = await db.execute(existing_user_query)
    if existing_user_result.scalar_one_or_none():
        raise ValidationException(
            "An account with this email address already exists",
            details={"email": "Email already registered"},
        )

    # Hash password with bcrypt
    hashed_pwd = hash_password(payload.password)

    new_user = User(
        email=clean_email,
        hashed_password=hashed_pwd,
        full_name=payload.full_name.strip() if payload.full_name else None,
        role="user",
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Issue JWT tokens
    access_token = create_access_token(
        subject=str(new_user.id),
        email=new_user.email,
        role=new_user.role,
    )
    refresh_token = create_refresh_token(subject=str(new_user.id))

    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(new_user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate User & Issue Tokens",
)
async def login(
    request: Request,
    response: Response,
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate email and password, returning signed access and refresh tokens.
    """
    await check_rate_limit(request, key_prefix="login", max_requests=5, window_seconds=60)

    clean_email = payload.email.strip().lower()

    query = select(User).where(User.email == clean_email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise UnauthorizedException("Invalid email or password")

    if not user.is_active:
        raise ForbiddenException("Your account is disabled. Please contact support.")

    # Issue tokens
    access_token = create_access_token(
        subject=str(user.id),
        email=user.email,
        role=user.role,
    )
    refresh_token = create_refresh_token(subject=str(user.id))

    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh Expired Access Token",
)
async def refresh_token(
    request: Request,
    response: Response,
    payload: Optional[RefreshTokenRequest] = None,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Exchange a valid refresh token for a fresh access token and rotated refresh token.
    Reads token from request payload or secure HttpOnly cookie.
    """
    await check_rate_limit(request, key_prefix="refresh", max_requests=10, window_seconds=60)

    token_str = None
    if payload and payload.refresh_token:
        token_str = payload.refresh_token
    else:
        token_str = request.cookies.get("ts_refresh_token")

    if not token_str:
        raise UnauthorizedException("Refresh token was not provided")

    decoded_payload = decode_token(token_str)
    if decoded_payload.get("type") != "refresh":
        raise UnauthorizedException("Invalid token type. Refresh token required")

    user_id_str = decoded_payload.get("sub")
    if not user_id_str:
        raise UnauthorizedException("Invalid token subject")

    query = select(User).where(User.id == user_id_str)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise UnauthorizedException("User account not found or is inactive")

    # Rotate tokens
    new_access_token = create_access_token(
        subject=str(user.id),
        email=user.email,
        role=user.role,
    )
    new_refresh_token = create_refresh_token(subject=str(user.id))

    _set_auth_cookies(response, new_access_token, new_refresh_token)

    return TokenResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=new_refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current Authenticated User",
)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """
    Returns the profile of the currently logged-in user.
    """
    return UserResponse.model_validate(current_user)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout User & Invalidate Cookies",
)
async def logout(response: Response) -> MessageResponse:
    """
    Clear authentication cookies.
    """
    response.delete_cookie(key="ts_access_token", path="/")
    response.delete_cookie(key="ts_refresh_token", path="/")
    return MessageResponse(message="Successfully logged out")
