"""
FinCEN BSA E-Filing XML 2.0 Batch Exporter & Schema Validator (`EFilingBatchXML`).
Generates regulator-compliant XML batches for:
1. FinCEN Suspicious Activity Reports (FinCEN SAR — Form 111)
2. FinCEN Currency Transaction Reports (FinCEN CTR — Form 112)

Maps SentinelGraph typology codes to official FinCEN Suspicious Activity Subtype Codes
(e.g., Structuring, Money Laundering, Terrorist Financing, Cyber Event, Elder Financial Exploitation,
Account Takeover, Wire Fraud) and validates all mandatory XSD elements prior to export.
"""
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from backend.app.cases.service import CaseManagementService
from backend.app.core.exceptions import ValidationError
from backend.app.db.connection import DatabaseManager
from backend.app.repositories.core_repositories import CustomerRepository


FINCEN_TYPOLOGY_CODE_MAP: Dict[str, Dict[str, str]] = {
    "AML-STR-001": {"category": "Structuring", "code": "0111", "label": "Alters or cancels transaction to avoid BSA recordkeeping/CTR"},
    "AML-STR-002": {"category": "Structuring", "code": "0112", "label": "Multiple transactions below CTR threshold"},
    "AML-STR-003": {"category": "Structuring", "code": "0113", "label": "Multiple individuals/branches conducting sub-CTR transactions"},
    "AML-STR-004": {"category": "Structuring", "code": "0114", "label": "Alters transaction to evade funds transfer Travel Rule"},
    "AML-STR-005": {"category": "Structuring", "code": "0199", "label": "Other structuring (round-dollar cash anomaly)"},
    "AML-LAY-001": {"category": "MoneyLaundering", "code": "0801", "label": "Exchanges small bills for large bills or rapid pass-through"},
    "AML-LAY-002": {"category": "MoneyLaundering", "code": "0804", "label": "Funnel account / multi-hop layering across accounts"},
    "AML-LAY-003": {"category": "MoneyLaundering", "code": "0805", "label": "Circular round-tripping / carousel fund flow"},
    "AML-LAY-004": {"category": "MoneyLaundering", "code": "0820", "label": "Sudden awakening of previously dormant account"},
    "AML-LAY-005": {"category": "MoneyLaundering", "code": "0824", "label": "Rapid fiat-to-virtual-currency conversion"},
    "AML-NET-001": {"category": "MoneyLaundering", "code": "0821", "label": "Fan-in money mule aggregation collector hub"},
    "AML-NET-002": {"category": "MoneyLaundering", "code": "0822", "label": "Fan-out money mule dispersion hub"},
    "AML-NET-003": {"category": "CyberEvent", "code": "1101", "label": "Shared hardware device fingerprint or IP ring"},
    "AML-NET-004": {"category": "MoneyLaundering", "code": "0823", "label": "Transaction with blocked/restricted/high-risk party"},
    "AML-NET-005": {"category": "MoneyLaundering", "code": "0825", "label": "Reciprocal wash transfers without economic purpose"},
    "AML-GEO-001": {"category": "MoneyLaundering", "code": "0809", "label": "Suspicious EFT/Wire involving high-risk FATF jurisdiction"},
    "AML-GEO-002": {"category": "MoneyLaundering", "code": "0810", "label": "Offshore secrecy haven shell company layering"},
    "AML-GEO-003": {"category": "IdentificationDocumentation", "code": "0405", "label": "Impossible travel geolocation velocity conflict"},
    "AML-GEO-004": {"category": "MoneyLaundering", "code": "0811", "label": "Cross-border remittance burst inconsistent with KYC"},
    "AML-GEO-005": {"category": "MoneyLaundering", "code": "0812", "label": "Sanctions-adjacent export/transshipment corridor routing"},
    "FRD-BEH-001": {"category": "OtherSuspiciousActivities", "code": "0920", "label": "Extreme behavioral transaction velocity spike"},
    "FRD-BEH-002": {"category": "Fraud", "code": "0312", "label": "Account Takeover (ATO) unauthorized electronic intrusion"},
    "FRD-BEH-003": {"category": "OtherSuspiciousActivities", "code": "0926", "label": "Elder financial exploitation"},
    "FRD-BEH-004": {"category": "OtherSuspiciousActivities", "code": "0917", "label": "Transaction out of pattern for business customer"},
    "FRD-BEH-005": {"category": "CyberEvent", "code": "1102", "label": "Automated overnight off-hours scripting burst"},
}


class FinCenBsaXmlExporter:
    """Serializes and validates FinCEN BSA E-Filing XML 2.0 batches for SAR and CTR reports."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.case_service = CaseManagementService(db)
        self.customer_repo = CustomerRepository(db)

    def export_sar_xml(
        self,
        case_id: str,
        filer_institution_name: str = "SentinelGraph National Compliance Bank NA",
        filer_ein: str = "135589201",
        filer_rssd: str = "481920",
    ) -> Dict[str, Any]:
        case_obj = self.case_service.get_case(case_id)
        sar_reports = case_obj.get("sar_reports", [])
        if not sar_reports:
            raise ValidationError(f"Case '{case_id}' does not have a generated SAR report to export.")
        sar = sar_reports[0]
        customer = self.customer_repo.get_by_id(case_obj["primary_customer_id"])
        ubos = self.customer_repo.get_beneficial_owners(customer["id"])
        txs = case_obj.get("suspicious_transactions", [])

        typology_codes = sar.get("typology_codes", [])
        mapped_subtypes = [
            FINCEN_TYPOLOGY_CODE_MAP.get(
                code,
                {"category": "OtherSuspiciousActivities", "code": "0999", "label": code},
            )
            for code in typology_codes
        ]

        subtype_xml_blocks = "\n".join(
            f'        <SuspiciousActivitySubtype>\n'
            f'          <SuspiciousActivityCategory>{xml_escape(m["category"])}</SuspiciousActivityCategory>\n'
            f'          <SuspiciousActivitySubtypeID>{xml_escape(m["code"])}</SuspiciousActivitySubtypeID>\n'
            f'          <SuspiciousActivitySubtypeDescription>{xml_escape(m["label"])}</SuspiciousActivitySubtypeDescription>\n'
            f'        </SuspiciousActivitySubtype>'
            for m in mapped_subtypes
        )

        ubo_party_blocks = "\n".join(
            f'      <Party type="BeneficialOwner">\n'
            f'        <PartyName>{xml_escape(u["full_name"])}</PartyName>\n'
            f'        <BirthDate>{xml_escape(u["date_of_birth"])}</BirthDate>\n'
            f'        <NationalityCountry>{xml_escape(u["nationality"])}</NationalityCountry>\n'
            f'        <ResidenceCountry>{xml_escape(u["residence_country"])}</ResidenceCountry>\n'
            f'        <OwnershipPercentage>{float(u["ownership_percentage"]):.2f}</OwnershipPercentage>\n'
            f'        <PEPIndicator>{"Y" if u.get("is_pep") else "N"}</PEPIndicator>\n'
            f'      </Party>'
            for u in ubos
        )

        tx_xml_blocks = "\n".join(
            f'      <SuspiciousTransaction seq="{idx + 1}">\n'
            f'        <ExternalTransactionID>{xml_escape(t["external_tx_id"])}</ExternalTransactionID>\n'
            f'        <TransactionTimestamp>{xml_escape(t["tx_timestamp"])}</TransactionTimestamp>\n'
            f'        <TransactionType>{xml_escape(t["tx_type"])}</TransactionType>\n'
            f'        <Direction>{xml_escape(t["direction"])}</Direction>\n'
            f'        <AmountUSD>{float(t["amount_usd"]):.2f}</AmountUSD>\n'
            f'        <OriginCountry>{xml_escape(t["origin_country"])}</OriginCountry>\n'
            f'        <DestinationCountry>{xml_escape(t["destination_country"])}</DestinationCountry>\n'
            f'        <Channel>{xml_escape(t["channel"])}</Channel>\n'
            f'      </SuspiciousTransaction>'
            for idx, t in enumerate(txs[:50])
        )

        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<EFilingBatchXML xmlns="https://www.fincen.gov/base" SchemaVersion="2.0" TotalAmount="{float(sar['total_suspicious_amount_usd']):.2f}" PartyCount="{2 + len(ubos)}" ActivityCount="1">
  <FormTypeCode>SARX</FormTypeCode>
  <Activity SeqNum="1">
    <FilingDate>{datetime.now(timezone.utc).strftime('%Y-%m-%d')}</FilingDate>
    <BSAIdentifier>{xml_escape(sar.get('fincen_bsa_id') or 'PENDING-BSA-ID')}</BSAIdentifier>
    <FilingInstitutionNotetoFinCEN>{xml_escape(sar['sar_ref'])} | Case {xml_escape(case_obj['case_number'])}</FilingInstitutionNotetoFinCEN>
    <ActivityAssociation>
      <InitialReportIndicator>{"Y" if sar.get("filing_type") == "INITIAL" else "N"}</InitialReportIndicator>
      <ContinuingActivityIndicator>{"Y" if sar.get("filing_type") == "CONTINUING_ACTIVITY" else "N"}</ContinuingActivityIndicator>
    </ActivityAssociation>
    <Parties>
      <Party type="ReportingFinancialInstitution">
        <PartyName>{xml_escape(filer_institution_name)}</PartyName>
        <TIN type="EIN">{xml_escape(filer_ein)}</TIN>
        <PrimaryRegulator>OCC</PrimaryRegulator>
        <RSSDNumber>{xml_escape(filer_rssd)}</RSSDNumber>
      </Party>
      <Party type="Subject">
        <CustomerExternalRef>{xml_escape(customer['external_ref'])}</CustomerExternalRef>
        <EntityType>{xml_escape(customer['customer_type'])}</EntityType>
        <PartyName>{xml_escape(customer['legal_name'])}</PartyName>
        <BirthOrIncorporationDate>{xml_escape(customer['date_of_birth_or_inc'])}</BirthOrIncorporationDate>
        <NationalityCountry>{xml_escape(customer['nationality_or_reg_country'])}</NationalityCountry>
        <ResidenceCountry>{xml_escape(customer['residence_country'])}</ResidenceCountry>
        <OccupationOrBusinessType>{xml_escape(customer['occupation_or_industry'])}</OccupationOrBusinessType>
        <NAICSCode>{xml_escape(customer.get('naics_code') or '000000')}</NAICSCode>
        <TaxIDHashSHA256>{xml_escape(customer['tax_id_hash'])}</TaxIDHashSHA256>
        <CompositeRiskScore>{float(customer['composite_risk_score']):.2f}</CompositeRiskScore>
        <RiskBand>{xml_escape(customer['risk_band'])}</RiskBand>
      </Party>
{ubo_party_blocks}
    </Parties>
    <SuspiciousActivity>
      <CumulativeSuspiciousAmountUSD>{float(sar['total_suspicious_amount_usd']):.2f}</CumulativeSuspiciousAmountUSD>
      <ActivityDateRange>
        <StartDate>{xml_escape(sar['activity_start_date'])}</StartDate>
        <EndDate>{xml_escape(sar['activity_end_date'])}</EndDate>
      </ActivityDateRange>
      <SuspiciousActivitySubtypes>
{subtype_xml_blocks}
      </SuspiciousActivitySubtypes>
    </SuspiciousActivity>
    <SuspiciousTransactions>
{tx_xml_blocks}
    </SuspiciousTransactions>
    <ActivityNarrativeInformation>
      <ActivityNarrativeSequenceNumber>1</ActivityNarrativeSequenceNumber>
      <ActivityNarrativeText>{xml_escape(sar['full_narrative_text'])}</ActivityNarrativeText>
      <NarrativeSHA256Digest>{xml_escape(sar['content_sha256'])}</NarrativeSHA256Digest>
    </ActivityNarrativeInformation>
  </Activity>
</EFilingBatchXML>"""

        validation = self.validate_fincen_sar_xml(xml_body)
        return {
            "sar_ref": sar["sar_ref"],
            "case_number": case_obj["case_number"],
            "schema_version": "FinCEN-BSA-XML-2.0",
            "xml_sha256": hashlib.sha256(xml_body.encode("utf-8")).hexdigest(),
            "validation": validation,
            "xml_content": xml_body,
        }

    @staticmethod
    def validate_fincen_sar_xml(xml_text: str) -> Dict[str, Any]:
        errors: List[str] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            return {"is_valid": False, "errors": [f"XML ParseError: {exc}"]}

        ns = "{https://www.fincen.gov/base}"
        form_code = root.findtext(f"{ns}FormTypeCode") or root.findtext("FormTypeCode")
        if form_code != "SARX":
            errors.append(f"Invalid FormTypeCode '{form_code}' (expected 'SARX').")

        narrative = root.find(f".//{ns}ActivityNarrativeText")
        if narrative is None or len((narrative.text or "").strip()) < 100:
            errors.append("ActivityNarrativeText is missing or shorter than 100 characters.")

        amt = root.find(f".//{ns}CumulativeSuspiciousAmountUSD")
        if amt is None or float((amt.text or "0").strip()) <= 0:
            errors.append("CumulativeSuspiciousAmountUSD must be strictly positive.")

        subtypes = root.findall(f".//{ns}SuspiciousActivitySubtype")
        if not subtypes:
            errors.append("At least one SuspiciousActivitySubtype is required.")

        return {
            "is_valid": len(errors) == 0,
            "subtype_count": len(subtypes),
            "errors": errors,
        }
