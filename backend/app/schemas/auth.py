from typing import Optional
from pydantic import BaseModel, EmailStr, Field

from app.schemas.user import UserResponse


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    full_name: Optional[str] = Field(None, max_length=255)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str
    user: UserResponse


class MessageResponse(BaseModel):
    message: str
