"""
ISO 20022 MX XML Parser, Travel Rule Auditor, and Sample Generator.
Supports:
- `pacs.008.001.08` (FIToFICustomerCreditTransfer)
- `pacs.009.001.08` (FinancialInstitutionCreditTransfer)
- `pain.001.001.09` (CustomerCreditTransferInitiation)
- `camt.053.001.08` (BankToCustomerStatement)

Performs structural validation, extracts Debtor/Creditor/UltimateParty/IntermediaryAgent
 chains, and executes FATF Recommendation 16 / 31 CFR 1010.410(e) Travel Rule checks.
"""
import hashlib
import uuid
from xml.sax.saxutils import escape as xml_escape
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.core.exceptions import ValidationError
from backend.app.iso20022.models import (
    AgentInstitutionRecord,
    ParsedWireTransferMessage,
    PartyIdentificationRecord,
    PostalAddressRecord,
    TravelRuleComplianceResult,
)


FX_RATES_TO_USD: Dict[str, float] = {
    "USD": 1.0,
    "EUR": 1.085,
    "GBP": 1.275,
    "CHF": 1.132,
    "AED": 0.2723,
    "INR": 0.0120,
    "SGD": 0.745,
    "JPY": 0.0066,
    "HKD": 0.1282,
}


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find_child(elem: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    if elem is None:
        return None
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def _find_children(elem: Optional[ET.Element], name: str) -> List[ET.Element]:
    if elem is None:
        return []
    return [child for child in elem if _strip_ns(child.tag) == name]


def _find_text(elem: Optional[ET.Element], path_parts: List[str], default: str = "") -> str:
    curr = elem
    for part in path_parts:
        curr = _find_child(curr, part)
        if curr is None:
            return default
    return (curr.text or "").strip() or default


class Iso20022MxParser:
    """Parses ISO 20022 MX XML documents into normalized `ParsedWireTransferMessage` objects."""

    TRAVEL_RULE_THRESHOLD_USD = 3000.0

    @classmethod
    def _parse_postal_address(cls, pstl_elem: Optional[ET.Element]) -> PostalAddressRecord:
        if pstl_elem is None:
            return PostalAddressRecord(country="US")
        addr_lines = [
            (line.text or "").strip()
            for line in _find_children(pstl_elem, "AdrLine")
            if (line.text or "").strip()
        ]
        return PostalAddressRecord(
            street_name=_find_text(pstl_elem, ["StrtNm"]) or None,
            building_number=_find_text(pstl_elem, ["BldgNb"]) or None,
            post_code=_find_text(pstl_elem, ["PstCd"]) or None,
            town_name=_find_text(pstl_elem, ["TwnNm"]) or None,
            country_sub_division=_find_text(pstl_elem, ["CtrySubDvsn"]) or None,
            country=_find_text(pstl_elem, ["Ctry"], default="US"),
            address_lines=addr_lines,
        )

    @classmethod
    def _parse_party(
        cls,
        party_elem: Optional[ET.Element],
        acct_elem: Optional[ET.Element],
        agent_elem: Optional[ET.Element],
    ) -> PartyIdentificationRecord:
        name = _find_text(party_elem, ["Nm"], default="")
        pstl = cls._parse_postal_address(_find_child(party_elem, "PstlAdr"))
        lei = _find_text(party_elem, ["Id", "OrgId", "LEI"]) or _find_text(
            party_elem, ["Id", "OrgId", "Othr", "Id"]
        )
        nat_id = _find_text(party_elem, ["Id", "PrvtId", "Othr", "Id"])
        dob = _find_text(party_elem, ["Id", "PrvtId", "DtAndPlcOfBirth", "BirthDt"])
        pob = _find_text(party_elem, ["Id", "PrvtId", "DtAndPlcOfBirth", "CityOfBirth"])

        iban = _find_text(acct_elem, ["Id", "IBAN"])
        other_acct = _find_text(acct_elem, ["Id", "Othr", "Id"])
        acct_id = iban or other_acct

        bic = _find_text(agent_elem, ["FinInstnId", "BICFI"]) or _find_text(
            agent_elem, ["FinInstnId", "BIC"]
        )
        bank_name = _find_text(agent_elem, ["FinInstnId", "Nm"])
        clr_id = _find_text(agent_elem, ["FinInstnId", "ClrSysMmbId", "MmbId"])

        return PartyIdentificationRecord(
            name=name,
            account_id=acct_id,
            iban_or_bban=iban or other_acct,
            bic_fi=bic or None,
            bank_name=bank_name or None,
            Clearing_system_member_id=clr_id or None,
            postal_address=pstl,
            national_id_or_lei=lei or nat_id or None,
            date_of_birth=dob or None,
            place_of_birth=pob or None,
        )

    @classmethod
    def audit_travel_rule(cls, msg: ParsedWireTransferMessage) -> TravelRuleComplianceResult:
        """
        Audits a parsed wire transfer message against FATF Recommendation 16 and
        31 CFR 1010.410(e) (BSA Travel Rule >= $3,000 USD).
        Also checks for wire-stripping markers (e.g., 'NONREF', 'NOTPROVIDED', stripped BICs).
        """
        orig_defects = msg.debtor.is_originator_complete()
        benef_defects = msg.creditor.is_beneficiary_complete()
        stripping_flags: List[str] = []
        cover_flags: List[str] = []

        remit_upper = (msg.remittance_unstructured or "").upper()
        for token in ("NONREF", "NOTPROVIDED", "STRIPPED", "OMITTED", "CONFIDENTIAL CLIENT", "BY ORDER OF CLIENT"):
            if token in remit_upper or token in (msg.debtor.name or "").upper():
                stripping_flags.append(f"WIRE_STRIPPING_TOKEN_DETECTED:{token}")

        if msg.end_to_end_id.upper() in ("NOTPROVIDED", "NONREF", "NONE"):
            stripping_flags.append("END_TO_END_ID_OMITTED_OR_NONREF")

        if msg.message_standard == "ISO20022_PACS009" and msg.interbank_settlement_amount_usd >= 10000.0:
            if not msg.ultimate_debtor and not msg.remittance_unstructured:
                cover_flags.append("PACS009_INSTITUTIONAL_TRANSFER_WITHOUT_UNDERLYING_CUSTOMER_DISCLOSURE")

        penalty = 0.0
        if msg.interbank_settlement_amount_usd >= cls.TRAVEL_RULE_THRESHOLD_USD:
            penalty += 18.0 * len(orig_defects) + 15.0 * len(benef_defects)
        penalty += 25.0 * len(stripping_flags) + 20.0 * len(cover_flags)

        is_compliant = (
            (len(orig_defects) == 0 and len(benef_defects) == 0)
            if msg.interbank_settlement_amount_usd >= cls.TRAVEL_RULE_THRESHOLD_USD
            else True
        ) and len(stripping_flags) == 0

        return TravelRuleComplianceResult(
            is_compliant=is_compliant,
            applicable_threshold_usd=cls.TRAVEL_RULE_THRESHOLD_USD,
            evaluated_amount_usd=msg.interbank_settlement_amount_usd,
            originator_defects=orig_defects,
            beneficiary_defects=benef_defects,
            intermediary_stripping_indicators=stripping_flags,
            cover_payment_mismatch_flags=cover_flags,
            risk_score_penalty=min(100.0, penalty),
            regulatory_citations=[
                "FATF Recommendation 16 (Wire Transfers & Travel Rule)",
                "31 CFR 1010.410(e) (BSA Transmittal of Funds Recordkeeping)",
                "Basel Committee Guidance on Due Diligence for Cover Payment Messages",
            ],
        )

    @classmethod
    def parse_xml(cls, xml_text: str) -> List[ParsedWireTransferMessage]:
        """Parses an ISO 20022 XML payload (`pacs.008`, `pacs.009`, `pain.001`, or `camt.053`)."""
        if not xml_text or "<" not in xml_text:
            raise ValidationError("Invalid or empty ISO 20022 XML payload.")
        raw_digest = hashlib.sha256(xml_text.strip().encode("utf-8")).hexdigest()
        try:
            root = ET.fromstring(xml_text.strip())
        except ET.ParseError as exc:
            raise ValidationError(f"Malformed ISO 20022 XML syntax: {exc}") from exc

        # Detect message standard from root or child element
        first_child = list(root)[0] if list(root) else None
        root_type = _strip_ns(first_child.tag) if first_child is not None else _strip_ns(root.tag)

        if root_type == "FIToFICstmrCdtTrf":
            return cls._parse_pacs008(first_child, raw_digest)
        if root_type == "FICdtTrf":
            return cls._parse_pacs009(first_child, raw_digest)
        if root_type == "CstmrCdtTrfInitn":
            return cls._parse_pain001(first_child, raw_digest)
        if root_type == "BkToCstmrStmt":
            return cls._parse_camt053(first_child, raw_digest)

        raise ValidationError(f"Unsupported ISO 20022 root message element '{root_type}'.")

    @classmethod
    def _parse_pacs008(cls, body: ET.Element, raw_digest: str) -> List[ParsedWireTransferMessage]:
        grp_hdr = _find_child(body, "GrpHdr")
        msg_id = _find_text(grp_hdr, ["MsgId"], default=f"MSG-{uuid.uuid4().hex[:8].upper()}")
        cre_dt = _find_text(grp_hdr, ["CreDtTm"], default=datetime.now(timezone.utc).isoformat())

        results: List[ParsedWireTransferMessage] = []
        for tx_info in _find_children(body, "CdtTrfTxInf"):
            e2e_id = _find_text(tx_info, ["PmtId", "EndToEndId"], default="NOTPROVIDED")
            uetr = _find_text(tx_info, ["PmtId", "UETR"], default=str(uuid.uuid4()))

            amt_elem = _find_child(tx_info, "IntrBkSttlmAmt")
            if amt_elem is None:
                amt_elem = _find_child(tx_info, "InstdAmt")
            ccy = amt_elem.attrib.get("Ccy", "USD") if amt_elem is not None else "USD"
            raw_amt = float((amt_elem.text or "0.0").strip()) if amt_elem is not None else 0.0
            usd_amt = round(raw_amt * FX_RATES_TO_USD.get(ccy.upper(), 1.0), 2)

            sttlm_dt = _find_text(tx_info, ["IntrBkSttlmDt"], default=cre_dt[:10])
            chrg_br = _find_text(tx_info, ["ChrgBr"], default="SHAR")

            debtor = cls._parse_party(
                _find_child(tx_info, "Dbtr"),
                _find_child(tx_info, "DbtrAcct"),
                _find_child(tx_info, "DbtrAgt"),
            )
            creditor = cls._parse_party(
                _find_child(tx_info, "Cdtr"),
                _find_child(tx_info, "CdtrAcct"),
                _find_child(tx_info, "CdtrAgt"),
            )

            ultmt_dbtr_el = _find_child(tx_info, "UltmtDbtr")
            ultmt_cdtr_el = _find_child(tx_info, "UltmtCdtr")
            ultmt_dbtr = cls._parse_party(ultmt_dbtr_el, None, None) if ultmt_dbtr_el is not None else None
            ultmt_cdtr = cls._parse_party(ultmt_cdtr_el, None, None) if ultmt_cdtr_el is not None else None

            agents: List[AgentInstitutionRecord] = []
            for tag, role in (
                ("InstgAgt", "INSTRUCTING"),
                ("InstdAgt", "INSTRUCTED"),
                ("IntrmyAgt1", "INTERMEDIARY_1"),
                ("IntrmyAgt2", "INTERMEDIARY_2"),
                ("DbtrAgt", "DEBTOR_AGENT"),
                ("CdtrAgt", "CREDITOR_AGENT"),
            ):
                ag_el = _find_child(tx_info, tag)
                if ag_el is not None:
                    bic = _find_text(ag_el, ["FinInstnId", "BICFI"]) or _find_text(ag_el, ["FinInstnId", "BIC"])
                    bname = _find_text(ag_el, ["FinInstnId", "Nm"])
                    ctry = bic[4:6] if len(bic) >= 6 else "US"
                    if bic or bname:
                        agents.append(AgentInstitutionRecord(bic=bic or "UNKNOWNBIC", name=bname or None, country_code=ctry, role=role))

            rmt_inf = _find_child(tx_info, "RmtInf")
            ustrd = " | ".join(
                (u.text or "").strip() for u in _find_children(rmt_inf, "Ustrd") if (u.text or "").strip()
            )
            purpose = _find_text(tx_info, ["Purp", "Cd"]) or None

            msg = ParsedWireTransferMessage(
                message_id=msg_id,
                message_standard="ISO20022_PACS008",
                creation_timestamp=cre_dt,
                end_to_end_id=e2e_id,
                uetr=uetr,
                instructed_amount=raw_amt,
                instructed_currency=ccy,
                interbank_settlement_amount_usd=usd_amt,
                settlement_date=sttlm_dt,
                charge_bearer=chrg_br,
                debtor=debtor,
                creditor=creditor,
                ultimate_debtor=ultmt_dbtr,
                ultimate_creditor=ultmt_cdtr,
                agents=agents,
                remittance_unstructured=ustrd,
                purpose_code=purpose,
                raw_digest_sha256=raw_digest,
            )
            msg.travel_rule_audit = cls.audit_travel_rule(msg)
            results.append(msg)

        return results

    @classmethod
    def _parse_pacs009(cls, body: ET.Element, raw_digest: str) -> List[ParsedWireTransferMessage]:
        grp_hdr = _find_child(body, "GrpHdr")
        msg_id = _find_text(grp_hdr, ["MsgId"], default=f"PACS009-{uuid.uuid4().hex[:8].upper()}")
        cre_dt = _find_text(grp_hdr, ["CreDtTm"], default=datetime.now(timezone.utc).isoformat())

        results: List[ParsedWireTransferMessage] = []
        for tx_info in _find_children(body, "CdtTrfTxInf"):
            e2e_id = _find_text(tx_info, ["PmtId", "EndToEndId"], default="NOTPROVIDED")
            uetr = _find_text(tx_info, ["PmtId", "UETR"], default=str(uuid.uuid4()))
            amt_elem = _find_child(tx_info, "IntrBkSttlmAmt")
            ccy = amt_elem.attrib.get("Ccy", "USD") if amt_elem is not None else "USD"
            raw_amt = float((amt_elem.text or "0.0").strip()) if amt_elem is not None else 0.0
            usd_amt = round(raw_amt * FX_RATES_TO_USD.get(ccy.upper(), 1.0), 2)

            dbtr_bic = _find_text(tx_info, ["Dbtr", "FinInstnId", "BICFI"], default="DBTRBANKUS33")
            cdtr_bic = _find_text(tx_info, ["Cdtr", "FinInstnId", "BICFI"], default="CDTRBANKVG22")

            debtor = PartyIdentificationRecord(
                name=_find_text(tx_info, ["Dbtr", "FinInstnId", "Nm"], default=dbtr_bic),
                account_id=_find_text(tx_info, ["DbtrAcct", "Id", "Othr", "Id"], default=f"NOSTRO-{dbtr_bic}"),
                iban_or_bban=f"NOSTRO-{dbtr_bic}",
                bic_fi=dbtr_bic,
                postal_address=PostalAddressRecord(country=dbtr_bic[4:6] if len(dbtr_bic) >= 6 else "US", town_name="Financial District"),
            )
            creditor = PartyIdentificationRecord(
                name=_find_text(tx_info, ["Cdtr", "FinInstnId", "Nm"], default=cdtr_bic),
                account_id=_find_text(tx_info, ["CdtrAcct", "Id", "Othr", "Id"], default=f"VOSTRO-{cdtr_bic}"),
                iban_or_bban=f"VOSTRO-{cdtr_bic}",
                bic_fi=cdtr_bic,
                postal_address=PostalAddressRecord(country=cdtr_bic[4:6] if len(cdtr_bic) >= 6 else "VG", town_name="Offshore Center"),
            )

            undrlyg = _find_child(tx_info, "UndrlygCstmrCdtTrf")
            ultmt_dbtr = None
            if undrlyg is not None:
                ultmt_dbtr = cls._parse_party(
                    _find_child(undrlyg, "Dbtr"),
                    _find_child(undrlyg, "DbtrAcct"),
                    _find_child(undrlyg, "DbtrAgt"),
                )

            ustrd = _find_text(tx_info, ["RmtInf", "Ustrd"])
            msg = ParsedWireTransferMessage(
                message_id=msg_id,
                message_standard="ISO20022_PACS009",
                creation_timestamp=cre_dt,
                end_to_end_id=e2e_id,
                uetr=uetr,
                instructed_amount=raw_amt,
                instructed_currency=ccy,
                interbank_settlement_amount_usd=usd_amt,
                settlement_date=cre_dt[:10],
                charge_bearer="SHAR",
                debtor=debtor,
                creditor=creditor,
                ultimate_debtor=ultmt_dbtr,
                remittance_unstructured=ustrd,
                raw_digest_sha256=raw_digest,
            )
            msg.travel_rule_audit = cls.audit_travel_rule(msg)
            results.append(msg)
        return results

    @classmethod
    def _parse_pain001(cls, body: ET.Element, raw_digest: str) -> List[ParsedWireTransferMessage]:
        grp_hdr = _find_child(body, "GrpHdr")
        msg_id = _find_text(grp_hdr, ["MsgId"], default=f"PAIN001-{uuid.uuid4().hex[:8].upper()}")
        cre_dt = _find_text(grp_hdr, ["CreDtTm"], default=datetime.now(timezone.utc).isoformat())

        results: List[ParsedWireTransferMessage] = []
        for pmt_inf in _find_children(body, "PmtInf"):
            debtor = cls._parse_party(
                _find_child(pmt_inf, "Dbtr"),
                _find_child(pmt_inf, "DbtrAcct"),
                _find_child(pmt_inf, "DbtrAgt"),
            )
            for tx_info in _find_children(pmt_inf, "CdtTrfTxInf"):
                e2e_id = _find_text(tx_info, ["PmtId", "EndToEndId"], default="NOTPROVIDED")
                amt_elem = _find_child(_find_child(tx_info, "Amt"), "InstdAmt")
                ccy = amt_elem.attrib.get("Ccy", "USD") if amt_elem is not None else "USD"
                raw_amt = float((amt_elem.text or "0.0").strip()) if amt_elem is not None else 0.0
                usd_amt = round(raw_amt * FX_RATES_TO_USD.get(ccy.upper(), 1.0), 2)

                creditor = cls._parse_party(
                    _find_child(tx_info, "Cdtr"),
                    _find_child(tx_info, "CdtrAcct"),
                    _find_child(tx_info, "CdtrAgt"),
                )
                ustrd = _find_text(tx_info, ["RmtInf", "Ustrd"])
                msg = ParsedWireTransferMessage(
                    message_id=msg_id,
                    message_standard="ISO20022_PAIN001",
                    creation_timestamp=cre_dt,
                    end_to_end_id=e2e_id,
                    uetr=str(uuid.uuid4()),
                    instructed_amount=raw_amt,
                    instructed_currency=ccy,
                    interbank_settlement_amount_usd=usd_amt,
                    settlement_date=cre_dt[:10],
                    charge_bearer="SHAR",
                    debtor=debtor,
                    creditor=creditor,
                    remittance_unstructured=ustrd,
                    raw_digest_sha256=raw_digest,
                )
                msg.travel_rule_audit = cls.audit_travel_rule(msg)
                results.append(msg)
        return results

    @classmethod
    def _parse_camt053(cls, body: ET.Element, raw_digest: str) -> List[ParsedWireTransferMessage]:
        grp_hdr = _find_child(body, "GrpHdr")
        msg_id = _find_text(grp_hdr, ["MsgId"], default=f"CAMT053-{uuid.uuid4().hex[:8].upper()}")
        cre_dt = _find_text(grp_hdr, ["CreDtTm"], default=datetime.now(timezone.utc).isoformat())

        results: List[ParsedWireTransferMessage] = []
        for stmt in _find_children(body, "Stmt"):
            stmt_acct = _find_text(stmt, ["Acct", "Id", "IBAN"]) or _find_text(stmt, ["Acct", "Id", "Othr", "Id"], default="ACCT-STMT")
            stmt_owner = _find_text(stmt, ["Acct", "Ownr", "Nm"], default="Statement Account Holder")
            for ntry in _find_children(stmt, "Ntry"):
                amt_elem = _find_child(ntry, "Amt")
                ccy = amt_elem.attrib.get("Ccy", "USD") if amt_elem is not None else "USD"
                raw_amt = float((amt_elem.text or "0.0").strip()) if amt_elem is not None else 0.0
                usd_amt = round(raw_amt * FX_RATES_TO_USD.get(ccy.upper(), 1.0), 2)
                cdt_dbt = _find_text(ntry, ["CdtDbtInd"], default="DBIT")

                debtor = PartyIdentificationRecord(
                    name=stmt_owner,
                    account_id=stmt_acct,
                    iban_or_bban=stmt_acct,
                    postal_address=PostalAddressRecord(country="US", town_name="New York"),
                )
                creditor = PartyIdentificationRecord(
                    name="Counterparty Statement Entry",
                    account_id="CP-STMT-001",
                    iban_or_bban="CP-STMT-001",
                    postal_address=PostalAddressRecord(country="US", town_name="New York"),
                )
                msg = ParsedWireTransferMessage(
                    message_id=msg_id,
                    message_standard="ISO20022_CAMT053",
                    creation_timestamp=cre_dt,
                    end_to_end_id=f"CAMT-{cdt_dbt}-{len(results)+1}",
                    uetr=str(uuid.uuid4()),
                    instructed_amount=raw_amt,
                    instructed_currency=ccy,
                    interbank_settlement_amount_usd=usd_amt,
                    settlement_date=cre_dt[:10],
                    charge_bearer="SHAR",
                    debtor=debtor,
                    creditor=creditor,
                    remittance_unstructured=_find_text(ntry, ["AddtlNtryInf"], default="Statement entry"),
                    raw_digest_sha256=raw_digest,
                )
                msg.travel_rule_audit = cls.audit_travel_rule(msg)
                results.append(msg)
        return results

    @staticmethod
    def build_sample_pacs008_xml(
        msg_id: str = "PACS008-2026-00091",
        end_to_end_id: str = "E2E-BALTIC-99102",
        amount: float = 48500.00,
        currency: str = "USD",
        debtor_name: str = "Baltic Horizon Trading Ltd",
        debtor_iban: str = "VG96BVI0000192837465",
        debtor_country: str = "VG",
        debtor_town: str = "Road Town, Tortola",
        creditor_name: str = "Caspian Meridian Petrochem Trading",
        creditor_iban: str = "AE070331234567890123456",
        creditor_country: str = "AE",
        creditor_town: str = "Dubai",
        remittance_info: str = "INV-2026-8841 Dual-Use CNC Microelectronics & Optics Settlement",
    ) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">
  <FIToFICstmrCdtTrf>
    <GrpHdr>
      <MsgId>{msg_id}</MsgId>
      <CreDtTm>2026-10-12T14:22:10Z</CreDtTm>
      <NbOfTxs>1</NbOfTxs>
      <SttlmInf>
        <SttlmMtd>INDA</SttlmMtd>
      </SttlmInf>
    </GrpHdr>
    <CdtTrfTxInf>
      <PmtId>
        <InstrId>INSTR-{msg_id}</InstrId>
        <EndToEndId>{end_to_end_id}</EndToEndId>
        <UETR>97ed4827-7b6f-4491-a06f-b548d5a7512d</UETR>
      </PmtId>
      <IntrBkSttlmAmt Ccy="{currency}">{amount:.2f}</IntrBkSttlmAmt>
      <IntrBkSttlmDt>2026-10-12</IntrBkSttlmDt>
      <ChrgBr>SHAR</ChrgBr>
      <InstgAgt>
        <FinInstnId>
          <BICFI>BVIOVGVGXXX</BICFI>
          <Nm>BVI International Offshore Bank</Nm>
        </FinInstnId>
      </InstgAgt>
      <InstdAgt>
        <FinInstnId>
          <BICFI>ETBKAEADXXX</BICFI>
          <Nm>Emirates Trade Correspondent Bank</Nm>
        </FinInstnId>
      </InstdAgt>
      <Dbtr>
        <Nm>{debtor_name}</Nm>
        <PstlAdr>
          <TwnNm>{debtor_town}</TwnNm>
          <Ctry>{debtor_country}</Ctry>
        </PstlAdr>
      </Dbtr>
      <DbtrAcct>
        <Id>
          <IBAN>{debtor_iban}</IBAN>
        </Id>
      </DbtrAcct>
      <DbtrAgt>
        <FinInstnId>
          <BICFI>BVIOVGVGXXX</BICFI>
        </FinInstnId>
      </DbtrAgt>
      <CdtrAgt>
        <FinInstnId>
          <BICFI>ETBKAEADXXX</BICFI>
        </FinInstnId>
      </CdtrAgt>
      <Cdtr>
        <Nm>{creditor_name}</Nm>
        <PstlAdr>
          <TwnNm>{creditor_town}</TwnNm>
          <Ctry>{creditor_country}</Ctry>
        </PstlAdr>
      </Cdtr>
      <CdtrAcct>
        <Id>
          <IBAN>{creditor_iban}</IBAN>
        </Id>
      </CdtrAcct>
      <Purp>
        <Cd>GDDS</Cd>
      </Purp>
      <RmtInf>
        <Ustrd>{xml_escape(remittance_info)}</Ustrd>
      </RmtInf>
    </CdtTrfTxInf>
  </FIToFICstmrCdtTrf>
</Document>"""
