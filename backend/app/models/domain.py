"""
Core domain enumerations and typed data structures for SentinelGraph.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CustomerType(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    BUSINESS = "BUSINESS"


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SanctionsStatus(str, Enum):
    CLEAR = "CLEAR"
    POTENTIAL_MATCH = "POTENTIAL_MATCH"
    CONFIRMED_MATCH = "CONFIRMED_MATCH"


class AccountType(str, Enum):
    CHECKING = "CHECKING"
    SAVINGS = "SAVINGS"
    COMMERCIAL_TREASURY = "COMMERCIAL_TREASURY"
    MERCHANT_SETTLEMENT = "MERCHANT_SETTLEMENT"
    CRYPTO_WALLET = "CRYPTO_WALLET"


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"
    RESTRICTED = "RESTRICTED"
    FROZEN = "FROZEN"
    CLOSED = "CLOSED"


class TransactionType(str, Enum):
    CASH_DEPOSIT = "CASH_DEPOSIT"
    CASH_WITHDRAWAL = "CASH_WITHDRAWAL"
    WIRE_DOMESTIC = "WIRE_DOMESTIC"
    WIRE_INTERNATIONAL = "WIRE_INTERNATIONAL"
    ACH_CREDIT = "ACH_CREDIT"
    ACH_DEBIT = "ACH_DEBIT"
    CARD_POS = "CARD_POS"
    CARD_ECOMMERCE = "CARD_ECOMMERCE"
    INTERNAL_TRANSFER = "INTERNAL_TRANSFER"
    CRYPTO_EXCHANGE = "CRYPTO_EXCHANGE"


class TransactionDirection(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


class TransactionChannel(str, Enum):
    BRANCH = "BRANCH"
    ATM = "ATM"
    ONLINE_WEB = "ONLINE_WEB"
    MOBILE_APP = "MOBILE_APP"
    API_GATEWAY = "API_GATEWAY"
    SWIFT_NET = "SWIFT_NET"


class TypologyFamily(str, Enum):
    STRUCTURING = "STRUCTURING"
    LAYERING = "LAYERING"
    MULE_NETWORK = "MULE_NETWORK"
    GEOGRAPHIC = "GEOGRAPHIC"
    BEHAVIORAL_FRAUD = "BEHAVIORAL_FRAUD"


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    IN_TRIAGE = "IN_TRIAGE"
    ESCALATED_TO_CASE = "ESCALATED_TO_CASE"
    DISMISSED_FALSE_POSITIVE = "DISMISSED_FALSE_POSITIVE"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW_L1 = "IN_REVIEW_L1"
    ESCALATED_L2 = "ESCALATED_L2"
    PENDING_QA_APPROVAL = "PENDING_QA_APPROVAL"
    SAR_APPROVED = "SAR_APPROVED"
    SAR_FILED = "SAR_FILED"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"
    CLOSED_NO_SAR = "CLOSED_NO_SAR"


@dataclass
class RuleTriggerResult:
    """Structured output emitted when a typology rule triggers on an account/customer."""
    rule_id: str
    rule_name: str
    family: str
    severity: str
    confidence_score: float
    customer_id: str
    account_id: str
    triggered_transaction_ids: List[str]
    trigger_narrative: str
    evidence_metrics: Dict[str, Any] = field(default_factory=dict)
    regulatory_citation: str = ""
