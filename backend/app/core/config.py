from typing import List, Union, Optional
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustShield"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database & Cache
    DATABASE_URL: str = "postgresql://trustshield:trustshield@localhost:5432/trustshield"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Security & Tokens
    JWT_SECRET_KEY: str = "change-this-secret"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    CORS_ORIGINS: Union[str, List[str]] = "http://localhost:5173"

    # External Threat Intelligence APIs
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = ""
    URLHAUS_AUTH_KEY: Optional[str] = ""
    VIRUSTOTAL_API_KEY: Optional[str] = ""

    # OAuth2 Providers (Google & GitHub)
    GOOGLE_CLIENT_ID: Optional[str] = ""
    GOOGLE_CLIENT_SECRET: Optional[str] = ""
    GITHUB_CLIENT_ID: Optional[str] = ""
    GITHUB_CLIENT_SECRET: Optional[str] = ""
    FRONTEND_URL: str = "http://localhost:5173"
    BACKEND_URL: str = "http://localhost:8000"

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    @property
    def cors_origins_list(self) -> List[str]:
        if isinstance(self.CORS_ORIGINS, list):
            return self.CORS_ORIGINS
        if isinstance(self.CORS_ORIGINS, str):
            return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]
        return ["http://localhost:5173"]

    @property
    def async_database_url(self) -> str:
        """
        Returns the asyncpg-compatible connection string for async SQLAlchemy.
        """
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url

    @property
    def sync_database_url(self) -> str:
        """
        Returns the sync psycopg2-compatible connection string for sync SQLAlchemy / Celery.
        """
        url = self.DATABASE_URL
        if url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql+asyncpg://", "postgresql://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql://", 1)
        return url


settings = Settings()

