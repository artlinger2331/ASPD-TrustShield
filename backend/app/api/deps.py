import uuid
from typing import Callable, List, Optional
from fastapi import Depends, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decode_token
from app.core.exceptions import UnauthorizedException, ForbiddenException
from app.db.session import get_db
from app.models.user import User

# OAuth2 scheme supporting standard Bearer token in Swagger docs and headers
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False,
)


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extracts and validates JWT access token from Authorization header or cookie.
    Retrieves the corresponding User from the database.
    """
    # Fallback to cookie if Authorization header is not set
    if not token:
        token = request.cookies.get("ts_access_token")

    if not token:
        raise UnauthorizedException("Authentication credentials were not provided")

    payload = decode_token(token)
    if payload.get("type") != "access":
        raise UnauthorizedException("Invalid token type. Access token expected")

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise UnauthorizedException("Malformed token subject")

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise UnauthorizedException("Invalid user ID format in token")

    query = select(User).where(User.id == user_uuid)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise UnauthorizedException("User not found or account was deleted")

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Ensures the authenticated user account is active.
    """
    if not current_user.is_active:
        raise ForbiddenException("User account is disabled or suspended")
    return current_user


def require_roles(allowed_roles: List[str]) -> Callable:
    """
    Role-Based Access Control (RBAC) dependency factory.
    Enforces user.role is in allowed_roles.
    """
    async def role_checker(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise ForbiddenException(
                f"Access denied. Required role: {', '.join(allowed_roles)}"
            )
        return current_user

    return role_checker
