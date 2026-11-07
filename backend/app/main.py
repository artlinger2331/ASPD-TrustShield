from contextlib import asynccontextmanager
from typing import Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.core.exceptions import AppException, format_error_response
from app.db.session import async_engine
from app.api.v1.health import router as health_v1_router
from app.api.v1.auth import router as auth_v1_router
from app.api.v1.oauth import router as oauth_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager for startup and graceful shutdown.
    """
    # Startup actions
    yield
    # Shutdown actions
    if async_engine is not None:
        await async_engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Intelligent Website Trust & Safety Platform API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# 1. CORS Middleware configuration for frontend integration (http://localhost:5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


# 2. Global Exception Handlers (Standardized SecOps Error Envelope)
@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    return JSONResponse(
        status_code=exc.status_code,
        content=format_error_response(
            code=exc.code,
            message=exc.message,
            details=exc.details,
        ),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=format_error_response(
            code="VALIDATION_ERROR",
            message="Invalid request payload or query parameters",
            details=exc.errors(),
        ),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=format_error_response(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected system error occurred while processing the request",
            details=str(exc) if settings.PROJECT_NAME != "Production" else {},
        ),
    )


# 3. Root Liveness Probe (GET /health)
@app.get(
    "/health",
    summary="Root Liveness Probe",
    status_code=status.HTTP_200_OK,
    tags=["Health"],
)
async def root_liveness() -> Dict[str, Any]:
    """
    Lightweight 200 OK liveness check for container orchestrators and load balancers.
    """
    return {
        "status": "ok",
        "service": settings.PROJECT_NAME.lower(),
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# 4. Include v1 API Routers
app.include_router(health_v1_router, prefix=settings.API_V1_STR)
app.include_router(auth_v1_router, prefix=settings.API_V1_STR)
app.include_router(oauth_v1_router, prefix=settings.API_V1_STR)

