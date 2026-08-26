"""
Pydantic request and response schemas for REST API validation.
Compatible with Pydantic v1.10+ / FastAPI.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserProfileResponse


class TransactionIngestRequest(BaseModel):
    external_tx_id: Optional[str] = None
    account_id: str
    counterparty_id: Optional[str] = None
    counterparty_account_id: Optional[str] = None
    tx_timestamp: Optional[str] = None
    tx_type: str
    direction: str
    amount_original: float = Field(..., gt=0)
    currency_original: str = "USD"
    fx_rate_to_usd: float = Field(1.0, gt=0)
    channel: str = "ONLINE_WEB"
    origin_country: str = "US"
    destination_country: str = "US"
    ip_address: Optional[str] = None
    device_fingerprint: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    mcc_code: Optional[str] = None
    branch_or_atm_id: Optional[str] = None
    remittance_purpose: Optional[str] = None
    evaluate_rules: bool = True


class AlertTriageRequest(BaseModel):
    action: str = Field(..., description="ASSIGN, DISMISS_FALSE_POSITIVE, or ESCALATE_TO_CASE")
    assigned_to_user_id: Optional[str] = None
    disposition_reason: Optional[str] = None
    case_title: Optional[str] = None
    case_priority: str = "HIGH"
    existing_case_id: Optional[str] = None


class CaseNoteCreateRequest(BaseModel):
    note_type: str = "INVESTIGATION_NOTE"
    content: str = Field(..., min_length=5, max_length=10000)
    attachment_hash: Optional[str] = None


class CaseStateTransitionRequest(BaseModel):
    target_status: str
    notes: str = Field(..., min_length=5, max_length=4000)
    disposition_summary: Optional[str] = None


class SARGenerationRequest(BaseModel):
    filing_type: str = "INITIAL"
    custom_why_how_addendum: Optional[str] = None
    auto_submit_for_qa: bool = False


class RuleUpdateRequest(BaseModel):
    parameters: Dict[str, Any]
    is_enabled: bool = True
    change_reason: str = Field(..., min_length=5, max_length=500)


class ShadowBacktestRequest(BaseModel):
    rule_id: str
    candidate_parameters: Dict[str, Any]
    notes: Optional[str] = None


class SanctionsScreenRequest(BaseModel):
    screened_name: str = Field(..., min_length=2, max_length=200)
    date_of_birth: Optional[str] = None
    country_code: Optional[str] = None
    customer_id: Optional[str] = None
    min_similarity_threshold: float = Field(0.72, ge=0.40, le=1.0)


class SanctionsHitDispositionRequest(BaseModel):
    disposition: str = Field(..., description="TRUE_MATCH, FALSE_POSITIVE, or POTENTIAL_MATCH_ESCALATED")
    review_notes: str = Field(..., min_length=5, max_length=2000)
