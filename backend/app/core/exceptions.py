from datetime import datetime, timezone
from typing import Any, Optional, Dict
from fastapi import status


class AppException(Exception):
    """
    Base exception class for all domain-specific TrustShield exceptions.
    """
    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Any] = None,
    ):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details
        super().__init__(message)


class DatabaseConnectionException(AppException):
    def __init__(
        self,
        message: str = "Database service unavailable or unreachable",
        code: str = "DATABASE_UNAVAILABLE",
        details: Optional[Any] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details,
        )


class NotFoundException(AppException):
    def __init__(
        self,
        message: str = "Requested resource was not found",
        code: str = "RESOURCE_NOT_FOUND",
        details: Optional[Any] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class ValidationException(AppException):
    def __init__(
        self,
        message: str = "Input validation failed",
        code: str = "VALIDATION_ERROR",
        details: Optional[Any] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class UnauthorizedException(AppException):
    def __init__(
        self,
        message: str = "Authentication credentials required or invalid",
        code: str = "UNAUTHORIZED",
        details: Optional[Any] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class ForbiddenException(AppException):
    def __init__(
        self,
        message: str = "Insufficient permissions to perform this action",
        code: str = "FORBIDDEN",
        details: Optional[Any] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class RateLimitException(AppException):
    def __init__(
        self,
        message: str = "Too many requests. Please slow down.",
        code: str = "RATE_LIMIT_EXCEEDED",
        details: Optional[Any] = None,
    ):
        super().__init__(
            message=message,
            code=code,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=details,
        )


def format_error_response(
    code: str,
    message: str,
    details: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Constructs a standardized SecOps-compliant JSON error envelope.
    """
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details if details is not None else {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }
