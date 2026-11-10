"""
Extended Pydantic Domain Validation Models (`backend/app/schemas/domain_schemas_extended.py`).
Provides explicit schema contracts, serialization logic, and field constraints for all
175 AML/Fraud typologies, ISO 20022 wire messages, FinCEN/FIU-IND filings, and audit records.
"""
from datetime import date, datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator


class StructuringParameterConfig(BaseModel):
    """Configuration thresholds for Structuring typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class StructuringTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered Structuring alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("STRUCTURING", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class StructuringAuditLogPayload(BaseModel):
    """Audit envelope for Structuring configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class LayeringParameterConfig(BaseModel):
    """Configuration thresholds for Layering typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class LayeringTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered Layering alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("LAYERING", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class LayeringAuditLogPayload(BaseModel):
    """Audit envelope for Layering configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class MuleNetworkParameterConfig(BaseModel):
    """Configuration thresholds for MuleNetwork typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class MuleNetworkTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered MuleNetwork alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("MULENETWORK", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class MuleNetworkAuditLogPayload(BaseModel):
    """Audit envelope for MuleNetwork configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class GeographicParameterConfig(BaseModel):
    """Configuration thresholds for Geographic typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class GeographicTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered Geographic alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("GEOGRAPHIC", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class GeographicAuditLogPayload(BaseModel):
    """Audit envelope for Geographic configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class BehavioralFraudParameterConfig(BaseModel):
    """Configuration thresholds for BehavioralFraud typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class BehavioralFraudTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered BehavioralFraud alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("BEHAVIORALFRAUD", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class BehavioralFraudAuditLogPayload(BaseModel):
    """Audit envelope for BehavioralFraud configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class TradeBasedMLParameterConfig(BaseModel):
    """Configuration thresholds for TradeBasedML typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class TradeBasedMLTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered TradeBasedML alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("TRADEBASEDML", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class TradeBasedMLAuditLogPayload(BaseModel):
    """Audit envelope for TradeBasedML configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class CorrespondentBankingParameterConfig(BaseModel):
    """Configuration thresholds for CorrespondentBanking typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class CorrespondentBankingTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered CorrespondentBanking alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("CORRESPONDENTBANKING", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class CorrespondentBankingAuditLogPayload(BaseModel):
    """Audit envelope for CorrespondentBanking configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class CryptoForensicsParameterConfig(BaseModel):
    """Configuration thresholds for CryptoForensics typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class CryptoForensicsTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered CryptoForensics alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("CRYPTOFORENSICS", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class CryptoForensicsAuditLogPayload(BaseModel):
    """Audit envelope for CryptoForensics configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class RbiPmlaParameterConfig(BaseModel):
    """Configuration thresholds for RbiPmla typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class RbiPmlaTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered RbiPmla alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("RBIPMLA", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class RbiPmlaAuditLogPayload(BaseModel):
    """Audit envelope for RbiPmla configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class EuUkRegimesParameterConfig(BaseModel):
    """Configuration thresholds for EuUkRegimes typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class EuUkRegimesTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered EuUkRegimes alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("EUUKREGIMES", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class EuUkRegimesAuditLogPayload(BaseModel):
    """Audit envelope for EuUkRegimes configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class CyberSyntheticFraudParameterConfig(BaseModel):
    """Configuration thresholds for CyberSyntheticFraud typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class CyberSyntheticFraudTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered CyberSyntheticFraud alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("CYBERSYNTHETICFRAUD", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class CyberSyntheticFraudAuditLogPayload(BaseModel):
    """Audit envelope for CyberSyntheticFraud configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class MaritimeSanctionsParameterConfig(BaseModel):
    """Configuration thresholds for MaritimeSanctions typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class MaritimeSanctionsTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered MaritimeSanctions alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("MARITIMESANCTIONS", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class MaritimeSanctionsAuditLogPayload(BaseModel):
    """Audit envelope for MaritimeSanctions configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class SupplyChainFinanceParameterConfig(BaseModel):
    """Configuration thresholds for SupplyChainFinance typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class SupplyChainFinanceTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered SupplyChainFinance alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("SUPPLYCHAINFINANCE", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class SupplyChainFinanceAuditLogPayload(BaseModel):
    """Audit envelope for SupplyChainFinance configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class WealthPrivateBankingParameterConfig(BaseModel):
    """Configuration thresholds for WealthPrivateBanking typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class WealthPrivateBankingTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered WealthPrivateBanking alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("WEALTHPRIVATEBANKING", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class WealthPrivateBankingAuditLogPayload(BaseModel):
    """Audit envelope for WealthPrivateBanking configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class MerchantPayFacParameterConfig(BaseModel):
    """Configuration thresholds for MerchantPayFac typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class MerchantPayFacTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered MerchantPayFac alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("MERCHANTPAYFAC", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class MerchantPayFacAuditLogPayload(BaseModel):
    """Audit envelope for MerchantPayFac configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None


class PublicSectorFraudParameterConfig(BaseModel):
    """Configuration thresholds for PublicSectorFraud typology evaluators."""
    min_amount_usd: float = Field(5000.0, ge=100.0, description="Minimum single transaction threshold")
    max_amount_usd: Optional[float] = Field(None, description="Upper bound for sub-threshold structuring")
    window_hours: int = Field(168, ge=1, le=720, description="Sliding evaluation window in hours")
    target_keywords: List[str] = Field(default_factory=list, description="Mandatory keyword triggers")
    min_occurrences: int = Field(2, ge=1, description="Minimum trigger count in window")
    kyc_deviation_factor: float = Field(1.5, ge=1.0, description="Multiplier against expected monthly volume")
    is_mandatory_sar_escalation: bool = Field(False, description="Flag for immediate L2 escalation")

    @validator('min_amount_usd')
    def validate_min_amount(cls, v: float) -> float:
        if v <= 0:
            raise ValueError('min_amount_usd must be positive')
        return round(v, 2)

class PublicSectorFraudTriggerEvidenceRecord(BaseModel):
    """Detailed evidence record for a triggered PublicSectorFraud alert."""
    rule_id: str = Field(..., min_length=5, max_length=20)
    rule_name: str = Field(..., min_length=3, max_length=120)
    typology_family: str = Field("PUBLICSECTORFRAUD", description="Typology family category")
    account_id: str = Field(..., min_length=5)
    customer_id: str = Field(..., min_length=5)
    cumulative_trigger_amount_usd: float = Field(..., ge=0.0)
    triggering_transaction_ids: List[str] = Field(..., min_items=1)
    confidence_percentage: float = Field(..., ge=0.0, le=100.0)
    evidence_breakdown: Dict[str, Any] = Field(default_factory=dict)
    regulatory_citation: str = Field(..., min_length=5)
    investigator_action_summary: str = Field(..., min_length=10)

class PublicSectorFraudAuditLogPayload(BaseModel):
    """Audit envelope for PublicSectorFraud configuration changes."""
    rule_id: str
    modified_by_user_id: str
    modification_timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_parameters: Dict[str, Any]
    updated_parameters: Dict[str, Any]
    justification_memo: str = Field(..., min_length=10)
    approval_ticket_ref: Optional[str] = None
