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
    REDIS_CACHE_ENABLED: bool = True
    DOMAIN_INTEL_CACHE_TTL: int = 86400  # 24 hours
    DNS_ANALYSIS_CACHE_TTL: int = 3600    # 1 hour

    # Domain & DNS Intelligence Providers
    WHOIS_PROVIDER: str = "rdap"         # 'rdap', 'whois', or 'mock'
    WHOIS_TIMEOUT: float = 3.5
    DNS_TIMEOUT: float = 2.0

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
    PHISHTANK_API_KEY: Optional[str] = ""
    OPENPHISH_API_KEY: Optional[str] = ""

    # Threat Intelligence Reliability & Caching
    THREAT_INTEL_REQUEST_TIMEOUT: float = 3.5
    THREAT_INTEL_MAX_RETRIES: int = 2
    THREAT_INTEL_CACHE_TTL: int = 3600
    THREAT_INTEL_CIRCUIT_FAILURE_THRESHOLD: int = 3
    THREAT_INTEL_CIRCUIT_COOLDOWN_SECONDS: float = 60.0
    ENABLED_THREAT_INTEL_PROVIDERS: List[str] = [
        "google_safe_browsing",
        "urlhaus",
        "phishtank",
        "openphish",
        "virustotal",
    ]

    # Machine Learning URL Classification Subsystem
    ENABLE_ML_CLASSIFICATION: bool = True
    ML_RISK_WEIGHT: float = 0.10
    ML_CACHE_TTL_SECONDS: int = 3600

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
        base_origins = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "https://aspd-trust-shield.vercel.app",
        ]
        if isinstance(self.CORS_ORIGINS, list):
            return list(set(self.CORS_ORIGINS + base_origins))
        if isinstance(self.CORS_ORIGINS, str):
            configured = [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]
            return list(set(configured + base_origins))
        return base_origins

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

