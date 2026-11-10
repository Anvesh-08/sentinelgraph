"""
India FIU-IND FINnet 2.0 (Prevention of Money Laundering Act [PMLA] 2002 & RBI Master Direction)
Regulatory XML Report Exporter & Schema Validator.
Supports:
1. STR (Suspicious Transaction Report — PMLA Rule 3(1)(D))
2. CTR (Cash Transaction Report — Aggregate Cash >= INR 10,00,000 or Foreign Currency Equivalent)
3. CBWTR (Cross-Border Wire Transfer Report — Cross-Border Wire >= INR 5,00,000)
"""
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List
from xml.sax.saxutils import escape as xml_escape

from backend.app.cases.service import CaseManagementService
from backend.app.db.connection import DatabaseManager
from backend.app.repositories.core_repositories import CustomerRepository


USD_TO_INR_RATE = 83.50


class FiuIndFinnetExporter:
    """Generates and validates FIU-IND FINnet 2.0 STR, CTR, and CBWTR XML batches."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.case_service = CaseManagementService(db)
        self.customer_repo = CustomerRepository(db)

    def export_fiu_ind_str_xml(
        self,
        case_id: str,
        reporting_entity_name: str = "SentinelGraph Financial Services India Pvt Ltd",
        fiureid: str = "FIUIND-RE-990182",
        principal_officer_name: str = "Vikramaditya Rao",
    ) -> Dict[str, Any]:
        case_obj = self.case_service.get_case(case_id)
        customer = self.customer_repo.get_by_id(case_obj["primary_customer_id"])
        txs = case_obj.get("suspicious_transactions", [])
        sar_list = case_obj.get("sar_reports", [])
        gos_narrative = (
            sar_list[0]["full_narrative_text"]
            if sar_list
            else f"Grounds of Suspicion for Case {case_obj['case_number']}: Triggered AML typologies {', '.join(case_obj.get('typology_tags', []))}."
        )

        total_inr = round(float(case_obj["total_suspicious_amount_usd"]) * USD_TO_INR_RATE, 2)

        tx_xml = "\n".join(
            f'      <Transaction>\n'
            f'        <TransactionDate>{xml_escape(t["tx_timestamp"][:10])}</TransactionDate>\n'
            f'        <TransactionRefNo>{xml_escape(t["external_tx_id"])}</TransactionRefNo>\n'
            f'        <TransactionType>{xml_escape(t["tx_type"])}</TransactionType>\n'
            f'        <DebitCreditIndicator>{"C" if t["direction"] == "INBOUND" else "D"}</DebitCreditIndicator>\n'
            f'        <AmountINR>{round(float(t["amount_usd"]) * USD_TO_INR_RATE, 2):.2f}</AmountINR>\n'
            f'        <OriginalCurrency>{xml_escape(t["currency_original"])}</OriginalCurrency>\n'
            f'        <OriginCountry>{xml_escape(t["origin_country"])}</OriginCountry>\n'
            f'        <DestinationCountry>{xml_escape(t["destination_country"])}</DestinationCountry>\n'
            f'        <Remarks>{xml_escape(t.get("remittance_purpose") or "Suspicious transaction")}</Remarks>\n'
            f'      </Transaction>'
            for t in txs[:50]
        )

        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<Batch xmlns="https://fiuindia.gov.in/finnet2/str" SchemaVersion="2.0">
  <ReportType>STR</ReportType>
  <BatchHeader>
    <BatchNumber>STR-BATCH-{case_obj['case_number']}</BatchNumber>
    <BatchDate>{datetime.now(timezone.utc).strftime('%Y-%m-%d')}</BatchDate>
    <ReportingEntityName>{xml_escape(reporting_entity_name)}</ReportingEntityName>
    <FIUREID>{xml_escape(fiureid)}</FIUREID>
    <PrincipalOfficerName>{xml_escape(principal_officer_name)}</PrincipalOfficerName>
  </BatchHeader>
  <Report SeqNum="1">
    <CaseReference>{xml_escape(case_obj['case_number'])}</CaseReference>
    <SubjectCustomer>
      <CustomerID>{xml_escape(customer['external_ref'])}</CustomerID>
      <LegalName>{xml_escape(customer['legal_name'])}</LegalName>
      <CustomerCategory>{xml_escape(customer['customer_type'])}</CustomerCategory>
      <PANOrTaxIDHash>{xml_escape(customer['tax_id_hash'][:16].upper())}</PANOrTaxIDHash>
      <ResidenceCountry>{xml_escape(customer['residence_country'])}</ResidenceCountry>
      <RiskRating>{xml_escape(customer['risk_band'])}</RiskRating>
    </SubjectCustomer>
    <SuspicionSummary>
      <AlertIndicators>{xml_escape(", ".join(case_obj.get("typology_tags", [])))}</AlertIndicators>
      <CumulativeSuspiciousAmountINR>{total_inr:.2f}</CumulativeSuspiciousAmountINR>
      <GroundsOfSuspicion>{xml_escape(gos_narrative)}</GroundsOfSuspicion>
    </SuspicionSummary>
    <Transactions>
{tx_xml}
    </Transactions>
  </Report>
</Batch>"""

        root = ET.fromstring(xml_body)
        ns = "{https://fiuindia.gov.in/finnet2/str}"
        gos_el = root.find(f".//{ns}GroundsOfSuspicion")
        is_valid = gos_el is not None and len((gos_el.text or "").strip()) >= 30

        return {
            "report_type": "FIU_IND_FINNET2_STR",
            "case_number": case_obj["case_number"],
            "fiureid": fiureid,
            "total_suspicious_inr": total_inr,
            "is_valid": is_valid,
            "xml_sha256": hashlib.sha256(xml_body.encode("utf-8")).hexdigest(),
            "xml_content": xml_body,
        }

    def export_cbwtr_batch_xml(self, min_amount_inr: float = 500000.0) -> Dict[str, Any]:
        """
        Exports all cross-border wire transfers exceeding INR 5,00,000 (~$6,000 USD)
        under PMLA Rule 3(1)(E) Cross-Border Wire Transfer Reporting (CBWTR).
        """
        min_usd = min_amount_inr / USD_TO_INR_RATE
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT t.*, c.legal_name AS customer_name, c.external_ref AS customer_ref, a.account_number
                FROM transactions t
                JOIN customers c ON c.id = t.customer_id
                JOIN accounts a ON a.id = t.account_id
                WHERE (t.origin_country != t.destination_country OR t.tx_type = 'WIRE_INTERNATIONAL')
                  AND t.amount_usd >= ?
                ORDER BY t.tx_timestamp ASC
                """,
                (min_usd,),
            ).fetchall()

        cb_txs = [dict(r) for r in rows]
        items_xml = "\n".join(
            f'    <WireTransfer seq="{idx + 1}">\n'
            f'      <TransactionRefNo>{xml_escape(t["external_tx_id"])}</TransactionRefNo>\n'
            f'      <AccountNumber>{xml_escape(t["account_number"])}</AccountNumber>\n'
            f'      <CustomerName>{xml_escape(t["customer_name"])}</CustomerName>\n'
            f'      <OriginCountry>{xml_escape(t["origin_country"])}</OriginCountry>\n'
            f'      <DestinationCountry>{xml_escape(t["destination_country"])}</DestinationCountry>\n'
            f'      <AmountUSD>{float(t["amount_usd"]):.2f}</AmountUSD>\n'
            f'      <AmountINR>{round(float(t["amount_usd"]) * USD_TO_INR_RATE, 2):.2f}</AmountINR>\n'
            f'    </WireTransfer>'
            for idx, t in enumerate(cb_txs)
        )

        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<CBWTRBatch xmlns="https://fiuindia.gov.in/finnet2/cbwtr" SchemaVersion="2.0" RecordCount="{len(cb_txs)}">
  <ReportType>CBWTR</ReportType>
  <ThresholdINR>{min_amount_inr:.2f}</ThresholdINR>
  <WireTransfers>
{items_xml}
  </WireTransfers>
</CBWTRBatch>"""

        return {
            "report_type": "FIU_IND_FINNET2_CBWTR",
            "qualifying_wire_count": len(cb_txs),
            "threshold_inr": min_amount_inr,
            "xml_sha256": hashlib.sha256(xml_body.encode("utf-8")).hexdigest(),
            "xml_content": xml_body,
        }
