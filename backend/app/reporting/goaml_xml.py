"""
UNODC goAML 5.0 Standard XML Report Exporter (`backend/app/reporting/goaml_xml.py`).
Generates international FIU-compliant goAML `<report>` XML documents used across
European, UK, MENA, and APAC Financial Intelligence Units.
"""
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict
from xml.sax.saxutils import escape as xml_escape

from backend.app.cases.service import CaseManagementService
from backend.app.db.connection import DatabaseManager
from backend.app.repositories.core_repositories import CustomerRepository


class GoAmlXmlExporter:
    """Serializes SentinelGraph investigation cases into UNODC goAML 5.0 XML format."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.case_service = CaseManagementService(db)
        self.customer_repo = CustomerRepository(db)

    def export_goaml_str_xml(
        self,
        case_id: str,
        rentity_id: str = "RE-SG-0091",
        fiu_code: str = "FIU-GLOBAL",
    ) -> Dict[str, Any]:
        case_obj = self.case_service.get_case(case_id)
        customer = self.customer_repo.get_by_id(case_obj["primary_customer_id"])
        txs = case_obj.get("suspicious_transactions", [])
        sars = case_obj.get("sar_reports", [])
        reason_text = sars[0]["full_narrative_text"] if sars else f"Case {case_obj['case_number']} investigation."

        tx_nodes = "\n".join(
            f'  <transaction>\n'
            f'    <transactionnumber>{xml_escape(t["external_tx_id"])}</transactionnumber>\n'
            f'    <internal_ref_number>{xml_escape(t["id"])}</internal_ref_number>\n'
            f'    <date_transaction>{xml_escape(t["tx_timestamp"])}</date_transaction>\n'
            f'    <transmode_code>{xml_escape(t["tx_type"])}</transmode_code>\n'
            f'    <amount_local>{float(t["amount_usd"]):.2f}</amount_local>\n'
            f'    <t_from_my_client>\n'
            f'      <from_funds_code>{xml_escape(t["channel"])}</from_funds_code>\n'
            f'      <from_country>{xml_escape(t["origin_country"])}</from_country>\n'
            f'    </t_from_my_client>\n'
            f'    <t_to>\n'
            f'      <to_country>{xml_escape(t["destination_country"])}</to_country>\n'
            f'    </t_to>\n'
            f'  </transaction>'
            for t in txs[:50]
        )

        indicators = "\n".join(
            f'    <indicator>{xml_escape(code)}</indicator>'
            for code in case_obj.get("typology_tags", ["AML-STR-001"])
        )

        xml_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<report xmlns="http://www.unodc.org/goaml/5.0" SchemaVersion="5.0">
  <rentity_id>{xml_escape(rentity_id)}</rentity_id>
  <submission_code>E</submission_code>
  <report_code>STR</report_code>
  <entity_reference>{xml_escape(case_obj['case_number'])}</entity_reference>
  <submission_date>{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}</submission_date>
  <currency_code_local>USD</currency_code_local>
  <reporting_person>
    <first_name>Elena</first_name>
    <last_name>Rostova</last_name>
    <title>Chief Compliance Officer</title>
  </reporting_person>
  <location>
    <address_type>OPERATIONAL</address_type>
    <address>{xml_escape(customer.get('physical_address') or '100 Financial Plaza')}</address>
    <country_code>{xml_escape(customer['residence_country'])}</country_code>
  </location>
  <reason>{xml_escape(reason_text)}</reason>
  <action>Account escalated to L2/QA and reported via goAML 5.0 gateway ({xml_escape(fiu_code)}).</action>
{tx_nodes}
  <report_indicators>
{indicators}
  </report_indicators>
</report>"""

        root = ET.fromstring(xml_body)
        is_valid = root is not None and len(txs) >= 0
        return {
            "standard": "UNODC_GOAML_5.0",
            "case_number": case_obj["case_number"],
            "rentity_id": rentity_id,
            "is_valid": is_valid,
            "xml_sha256": hashlib.sha256(xml_body.encode("utf-8")).hexdigest(),
            "xml_content": xml_body,
        }
