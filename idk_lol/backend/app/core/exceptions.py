"""Application exceptions and standardized error handling."""

from typing import Any, Dict, Optional


class AppException(Exception):
    """Base application exception with an HTTP status and an error code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


class NotFoundError(AppException):
    def __init__(self, resource: str, target_id: Any = None) -> None:
        message = f"{resource} not found" if target_id is None else f"{resource} not found: {target_id}"
        super().__init__(404, "not_found", message, {"resource": resource, "id": str(target_id) if target_id else None})


class AuthorizationError(AppException):
    def __init__(self, message: str = "Not authorized to perform this action") -> None:
        super().__init__(403, "forbidden", message)


class AuthenticationError(AppException):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(401, "unauthorized", message)


class ValidationError(AppException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(400, "validation_error", message, details)


class ConflictError(AppException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(409, "conflict", message, details)


class UnprocessableEntityError(AppException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(422, "unprocessable_entity", message, details)


class ExternalServiceError(AppException):
    def __init__(self, service: str, message: str) -> None:
        super().__init__(
            502,
            "external_service_error",
            f"External service {service} unavailable: {message}",
            {"service": service},
        )