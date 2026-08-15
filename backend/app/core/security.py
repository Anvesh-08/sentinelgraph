"""
Cryptographic security primitives, PBKDF2-HMAC-SHA256 password hashing,
stateless HMAC-SHA256 bearer token issuance/verification, and RBAC matrices.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Iterable, Optional, Set

from backend.app.core.config import settings
from backend.app.core.exceptions import AuthenticationError, AuthorizationError


class Role:
    L1_ANALYST = "L1_ANALYST"
    L2_INVESTIGATOR = "L2_INVESTIGATOR"
    QA_COMPLIANCE_OFFICER = "QA_COMPLIANCE_OFFICER"
    RISK_ENGINEER = "RISK_ENGINEER"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"

    ALL_ROLES: Set[str] = {
        L1_ANALYST,
        L2_INVESTIGATOR,
        QA_COMPLIANCE_OFFICER,
        RISK_ENGINEER,
        SYSTEM_ADMIN,
    }


class Permission:
    VIEW_DASHBOARD = "VIEW_DASHBOARD"
    VIEW_CUSTOMERS = "VIEW_CUSTOMERS"
    RECALCULATE_RISK = "RECALCULATE_RISK"
    INGEST_TRANSACTIONS = "INGEST_TRANSACTIONS"
    TRIAGE_ALERT = "TRIAGE_ALERT"
    MANAGE_CASE_L1_L2 = "MANAGE_CASE_L1_L2"
    DRAFT_SAR = "DRAFT_SAR"
    APPROVE_QA_AND_FILE_SAR = "APPROVE_QA_AND_FILE_SAR"
    TUNE_RULES_AND_SIMULATE = "TUNE_RULES_AND_SIMULATE"
    SCREEN_SANCTIONS = "SCREEN_SANCTIONS"
    VERIFY_AUDIT_LEDGER = "VERIFY_AUDIT_LEDGER"


ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    Role.L1_ANALYST: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_CUSTOMERS,
        Permission.TRIAGE_ALERT,
        Permission.MANAGE_CASE_L1_L2,
        Permission.SCREEN_SANCTIONS,
    },
    Role.L2_INVESTIGATOR: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_CUSTOMERS,
        Permission.RECALCULATE_RISK,
        Permission.TRIAGE_ALERT,
        Permission.MANAGE_CASE_L1_L2,
        Permission.DRAFT_SAR,
        Permission.SCREEN_SANCTIONS,
    },
    Role.QA_COMPLIANCE_OFFICER: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_CUSTOMERS,
        Permission.RECALCULATE_RISK,
        Permission.TRIAGE_ALERT,
        Permission.MANAGE_CASE_L1_L2,
        Permission.DRAFT_SAR,
        Permission.APPROVE_QA_AND_FILE_SAR,
        Permission.SCREEN_SANCTIONS,
        Permission.VERIFY_AUDIT_LEDGER,
    },
    Role.RISK_ENGINEER: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_CUSTOMERS,
        Permission.RECALCULATE_RISK,
        Permission.INGEST_TRANSACTIONS,
        Permission.TUNE_RULES_AND_SIMULATE,
        Permission.SCREEN_SANCTIONS,
    },
    Role.SYSTEM_ADMIN: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_CUSTOMERS,
        Permission.RECALCULATE_RISK,
        Permission.INGEST_TRANSACTIONS,
        Permission.TRIAGE_ALERT,
        Permission.MANAGE_CASE_L1_L2,
        Permission.DRAFT_SAR,
        Permission.APPROVE_QA_AND_FILE_SAR,
        Permission.TUNE_RULES_AND_SIMULATE,
        Permission.SCREEN_SANCTIONS,
        Permission.VERIFY_AUDIT_LEDGER,
    },
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))


def hash_password(password: str, salt_hex: Optional[str] = None) -> Dict[str, str]:
    """
    Hashes a plaintext password using PBKDF2-HMAC-SHA256 with 210,000 iterations.
    Returns both the hex digest and the 16-byte random salt hex.
    """
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if salt_hex is None:
        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        settings.pbkdf2_iterations,
    )
    return {
        "password_hash": derived.hex(),
        "password_salt": salt_hex,
    }


def verify_password(password: str, expected_hash_hex: str, salt_hex: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2 hash in constant time."""
    if not password or not expected_hash_hex or not salt_hex:
        return False
    computed = hash_password(password, salt_hex=salt_hex)["password_hash"]
    return hmac.compare_digest(computed, expected_hash_hex)


def hash_tax_id(raw_tax_id: str) -> str:
    """Produces a deterministic privacy-preserving SHA-256 digest of a normalized Tax ID."""
    normalized = "".join(ch for ch in raw_tax_id.strip().upper() if ch.isalnum())
    return hashlib.sha256(f"SENTINELGRAPH_TIN:{normalized}".encode("utf-8")).hexdigest()


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    full_name: str = "",
    ttl_seconds: Optional[int] = None,
) -> str:
    """Issues a stateless HMAC-SHA256 signed bearer token."""
    if role not in Role.ALL_ROLES:
        raise ValueError(f"Unsupported role '{role}'.")
    now = int(time.time())
    exp = now + (ttl_seconds if ttl_seconds is not None else settings.token_ttl_seconds)
    header = {"alg": "HS256", "typ": "SG-JWT"}
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "full_name": full_name,
        "iat": now,
        "exp": exp,
        "jti": secrets.token_hex(8),
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(
        settings.token_secret.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_and_verify_token(token: str) -> Dict[str, Any]:
    """Verifies token signature and expiration in constant time, returning claims."""
    if not token or token.count(".") != 2:
        raise AuthenticationError("Malformed authentication token.")
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(
        settings.token_secret.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    try:
        provided_sig = _b64url_decode(sig_b64)
        payload_raw = _b64url_decode(payload_b64)
        claims: Dict[str, Any] = json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise AuthenticationError("Invalid token encoding.") from exc

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise AuthenticationError("Token signature verification failed.")

    now = int(time.time())
    if int(claims.get("exp", 0)) < now:
        raise AuthenticationError("Authentication token has expired.")

    return claims


def assert_permission(user_role: str, required_permission: str) -> None:
    """Raises AuthorizationError if user_role does not grant required_permission."""
    allowed = ROLE_PERMISSIONS.get(user_role, set())
    if required_permission not in allowed:
        raise AuthorizationError(
            f"Role '{user_role}' does not have required permission '{required_permission}'.",
            details={"role": user_role, "required_permission": required_permission},
        )


def assert_any_role(user_role: str, allowed_roles: Iterable[str]) -> None:
    allowed_set = set(allowed_roles)
    if user_role not in allowed_set:
        raise AuthorizationError(
            f"Role '{user_role}' is not authorized. Allowed roles: {sorted(allowed_set)}",
            details={"role": user_role, "allowed_roles": sorted(allowed_set)},
        )
