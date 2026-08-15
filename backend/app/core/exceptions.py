"""
Domain exception hierarchy for SentinelGraph.
Every exception maps deterministically to an HTTP status code and error code.
"""
from typing import Any, Dict, Optional


class SentinelGraphError(Exception):
    """Base exception for all domain and operational errors in SentinelGraph."""

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": {
                "code": self.error_code,
                "message": self.message,
                "details": self.details,
            }
        }


class AuthenticationError(SentinelGraphError):
    """Raised when credentials or bearer tokens are invalid or expired."""

    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="AUTHENTICATION_FAILED", status_code=401, details=details)


class AuthorizationError(SentinelGraphError):
    """Raised when an authenticated user lacks role permissions for an operation."""

    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="INSUFFICIENT_PERMISSIONS", status_code=403, details=details)


class SeparationOfDutiesError(SentinelGraphError):
    """Raised when Four-Eyes compliance rules are violated (e.g., investigator self-approving QA)."""

    def __init__(
        self,
        message: str = "Four-Eyes Separation of Duties Violation: The investigating analyst cannot QA-approve or file their own case.",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, error_code="SEPARATION_OF_DUTIES_VIOLATION", status_code=403, details=details)


class ResourceNotFoundError(SentinelGraphError):
    """Raised when a requested entity ID does not exist."""

    def __init__(self, entity_type: str, entity_id: str) -> None:
        super().__init__(
            f"{entity_type} '{entity_id}' was not found.",
            error_code="RESOURCE_NOT_FOUND",
            status_code=404,
            details={"entity_type": entity_type, "entity_id": entity_id},
        )


class ValidationError(SentinelGraphError):
    """Raised when domain invariants or input payloads fail validation."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="VALIDATION_ERROR", status_code=422, details=details)


class StateTransitionError(SentinelGraphError):
    """Raised when an invalid alert, case, or SAR state transition is attempted."""

    def __init__(self, entity_type: str, current_state: str, target_state: str, reason: str = "") -> None:
        msg = f"Invalid {entity_type} state transition from '{current_state}' to '{target_state}'."
        if reason:
            msg = f"{msg} {reason}"
        super().__init__(
            msg,
            error_code="INVALID_STATE_TRANSITION",
            status_code=409,
            details={
                "entity_type": entity_type,
                "current_state": current_state,
                "target_state": target_state,
                "reason": reason,
            },
        )


class AuditIntegrityError(SentinelGraphError):
    """Raised when cryptographic audit chain verification detects tampering."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, error_code="AUDIT_CHAIN_TAMPERED", status_code=500, details=details)
