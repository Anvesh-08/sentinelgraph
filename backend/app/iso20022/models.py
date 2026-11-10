"""
Domain data structures for ISO 20022 MX messages (`pacs.008`, `pacs.009`, `pain.001`, `camt.053`)
and SWIFT FIN MT messages (`MT103`, `MT202`, `MT202COV`), including FATF Recommendation 16 /
BSA 31 CFR 1010.410(e) Travel Rule completeness audit results.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PostalAddressRecord:
    street_name: Optional[str] = None
    building_number: Optional[str] = None
    post_code: Optional[str] = None
    town_name: Optional[str] = None
    country_sub_division: Optional[str] = None
    country: str = "US"
    address_lines: List[str] = field(default_factory=list)

    def is_complete_for_travel_rule(self) -> bool:
        has_country = bool(self.country and len(self.country.strip()) == 2)
        has_locality = bool(self.town_name or self.address_lines or self.street_name)
        return has_country and has_locality

    def to_single_line(self) -> str:
        parts = [
            p for p in [
                self.building_number,
                self.street_name,
                self.town_name,
                self.country_sub_division,
                self.post_code,
                self.country,
            ] if p
        ]
        if self.address_lines:
            parts = list(self.address_lines) + [self.country]
        return ", ".join(parts)


@dataclass
class PartyIdentificationRecord:
    name: str
    account_id: str
    iban_or_bban: str
    bic_fi: Optional[str] = None
    bank_name: Optional[str] = None
    Clearing_system_member_id: Optional[str] = None
    postal_address: PostalAddressRecord = field(default_factory=PostalAddressRecord)
    national_id_or_lei: Optional[str] = None
    date_of_birth: Optional[str] = None
    place_of_birth: Optional[str] = None

    def is_originator_complete(self) -> List[str]:
        defects: List[str] = []
        if not self.name or len(self.name.strip()) < 3 or self.name.strip().upper() in ("UNKNOWN", "CASH CUSTOMER", "N/A", "CLIENT"):
            defects.append("MISSING_OR_PLACEHOLDER_ORIGINATOR_NAME")
        if not self.account_id and not self.iban_or_bban:
            defects.append("MISSING_ORIGINATOR_ACCOUNT_IDENTIFIER")
        if not self.postal_address.is_complete_for_travel_rule() and not self.national_id_or_lei and not self.date_of_birth:
            defects.append("MISSING_ORIGINATOR_ADDRESS_OR_NATIONAL_ID")
        return defects

    def is_beneficiary_complete(self) -> List[str]:
        defects: List[str] = []
        if not self.name or len(self.name.strip()) < 2 or self.name.strip().upper() in ("UNKNOWN", "BEARER", "N/A"):
            defects.append("MISSING_OR_PLACEHOLDER_BENEFICIARY_NAME")
        if not self.account_id and not self.iban_or_bban:
            defects.append("MISSING_BENEFICIARY_ACCOUNT_IDENTIFIER")
        return defects


@dataclass
class AgentInstitutionRecord:
    bic: str
    name: Optional[str] = None
    country_code: str = "US"
    clearing_code: Optional[str] = None
    role: str = "INTERMEDIARY"  # INSTRUCTING, INSTRUCTED, INTERMEDIARY_1, INTERMEDIARY_2, DEBTOR_AGENT, CREDITOR_AGENT


@dataclass
class TravelRuleComplianceResult:
    is_compliant: bool
    applicable_threshold_usd: float
    evaluated_amount_usd: float
    originator_defects: List[str] = field(default_factory=list)
    beneficiary_defects: List[str] = field(default_factory=list)
    intermediary_stripping_indicators: List[str] = field(default_factory=list)
    cover_payment_mismatch_flags: List[str] = field(default_factory=list)
    risk_score_penalty: float = 0.0
    regulatory_citations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_compliant": self.is_compliant,
            "applicable_threshold_usd": self.applicable_threshold_usd,
            "evaluated_amount_usd": self.evaluated_amount_usd,
            "originator_defects": self.originator_defects,
            "beneficiary_defects": self.beneficiary_defects,
            "intermediary_stripping_indicators": self.intermediary_stripping_indicators,
            "cover_payment_mismatch_flags": self.cover_payment_mismatch_flags,
            "risk_score_penalty": round(self.risk_score_penalty, 2),
            "regulatory_citations": self.regulatory_citations,
        }


@dataclass
class ParsedWireTransferMessage:
    message_id: str
    message_standard: str  # ISO20022_PACS008, ISO20022_PACS009, ISO20022_PAIN001, ISO20022_CAMT053, SWIFT_MT103, SWIFT_MT202, SWIFT_MT202COV
    creation_timestamp: str
    end_to_end_id: str
    uetr: str
    instructed_amount: float
    instructed_currency: str
    interbank_settlement_amount_usd: float
    settlement_date: str
    charge_bearer: str  # DEBT, CRED, SHAR, SLEV
    debtor: PartyIdentificationRecord
    creditor: PartyIdentificationRecord
    ultimate_debtor: Optional[PartyIdentificationRecord] = None
    ultimate_creditor: Optional[PartyIdentificationRecord] = None
    agents: List[AgentInstitutionRecord] = field(default_factory=list)
    remittance_unstructured: str = ""
    remittance_structured_invoices: List[str] = field(default_factory=list)
    purpose_code: Optional[str] = None
    regulatory_reporting_codes: List[str] = field(default_factory=list)
    travel_rule_audit: Optional[TravelRuleComplianceResult] = None
    raw_digest_sha256: str = ""

    def to_sentinelgraph_tx_payload(
        self,
        internal_account_id: str,
        direction: str = "OUTBOUND",
        counterparty_id: Optional[str] = None,
        counterparty_account_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tx_type = (
            "WIRE_INTERNATIONAL"
            if self.debtor.postal_address.country != self.creditor.postal_address.country
            else "WIRE_DOMESTIC"
        )
        return {
            "external_tx_id": f"{self.message_standard}-{self.end_to_end_id}",
            "account_id": internal_account_id,
            "counterparty_id": counterparty_id,
            "counterparty_account_id": counterparty_account_id,
            "tx_timestamp": self.creation_timestamp,
            "tx_type": tx_type,
            "direction": direction,
            "amount_original": self.instructed_amount,
            "currency_original": self.instructed_currency,
            "fx_rate_to_usd": round(self.interbank_settlement_amount_usd / max(0.01, self.instructed_amount), 6),
            "amount_usd": self.interbank_settlement_amount_usd,
            "channel": "SWIFT_NET",
            "origin_country": self.debtor.postal_address.country,
            "destination_country": self.creditor.postal_address.country,
            "remittance_purpose": self.remittance_unstructured or f"ISO20022 {self.purpose_code or 'WIRE'}",
            "scenario_tag": (
                "SCENARIO_WIRE_STRIPPING"
                if (self.travel_rule_audit and not self.travel_rule_audit.is_compliant)
                else "ISO20022_INGESTED"
            ),
        }
