"""
SWIFT FIN MT103 (Single Customer Credit Transfer), MT202 (General Financial Institution Transfer),
and MT202COV (Cover Payment) Parser & Wire-Stripping Forensics Analyzer.

Parses standard SWIFT FIN Blocks (`{1:...}{2:...}{3:...}{4:\n:20:...\n-}{5:...}`) and extracts:
- `:20:` Transaction Reference Number
- `:23B:` Bank Operation Code (`CRED`, `SPAY`, `SSTD`)
- `:32A:` Value Date, Currency Code, Settlement Amount
- `:33B:` Currency / Original Instructed Amount
- `:50K:` / `:50A:` / `:50F:` Ordering Customer (Originator)
- `:52A:` Ordering Institution
- `:53A:` / `:54A:` / `:56A:` Correspondent & Intermediary Institutions
- `:57A:` Account With Institution
- `:59:` / `:59A:` Beneficiary Customer
- `:70:` Remittance Information
- `:71A:` Details of Charges (`OUR`, `SHA`, `BEN`)
- `:72:` Sender to Receiver Information (checked for sanctions circumvention / wire-stripping instructions)
"""
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from backend.app.core.exceptions import ValidationError
from backend.app.iso20022.models import (
    AgentInstitutionRecord,
    ParsedWireTransferMessage,
    PartyIdentificationRecord,
    PostalAddressRecord,
)
from backend.app.iso20022.mx_parser import FX_RATES_TO_USD, Iso20022MxParser


TAG_RE = re.compile(r"^:([0-9]{2}[A-Z]?):(.*)$")


class SwiftMtParser:
    """Parses SWIFT MT103, MT202, and MT202COV messages and detects wire-stripping patterns."""

    @staticmethod
    def _extract_block4_fields(raw_mt: str) -> Tuple[str, Dict[str, List[str]]]:
        msg_type = "MT103"
        b2_match = re.search(r"\{2:[IO](103|202COV|202)", raw_mt)
        if b2_match:
            msg_type = f"MT{b2_match.group(1)}"
        elif ":50A:" not in raw_mt and ":50K:" not in raw_mt and ":58A:" in raw_mt:
            msg_type = "MT202"

        b4_match = re.search(r"\{4:\s*(.*?)\s*-\}", raw_mt, flags=re.DOTALL)
        body = b4_match.group(1) if b4_match else raw_mt

        fields: Dict[str, List[str]] = {}
        current_tag: Optional[str] = None
        current_lines: List[str] = []

        for raw_line in body.splitlines():
            line = raw_line.strip("\r")
            if line == "-}" or not line.strip():
                continue
            m = TAG_RE.match(line.strip())
            if m:
                if current_tag is not None:
                    fields.setdefault(current_tag, []).append("\n".join(current_lines).strip())
                current_tag = m.group(1)
                current_lines = [m.group(2).strip()]
            elif current_tag is not None:
                current_lines.append(line.strip())

        if current_tag is not None:
            fields.setdefault(current_tag, []).append("\n".join(current_lines).strip())

        if "202" in msg_type and any(k.startswith("50") for k in fields) and any(k.startswith("59") for k in fields):
            msg_type = "MT202COV"

        return msg_type, fields

    @staticmethod
    def _parse_32a(val_32a: str) -> Tuple[str, str, float]:
        """Parses `:32A:YYMMDDCCCAMOUNT` (e.g., `261012USD48500,00`)."""
        cleaned = val_32a.strip()
        if len(cleaned) < 10:
            raise ValidationError(f"Malformed SWIFT :32A: field '{val_32a}'.")
        yy, mm, dd = cleaned[0:2], cleaned[2:4], cleaned[4:6]
        iso_date = f"20{yy}-{mm}-{dd}"
        ccy = cleaned[6:9].upper()
        amt_str = cleaned[9:].replace(",", ".").strip()
        amount = float(amt_str)
        return iso_date, ccy, amount

    @staticmethod
    def _parse_party_block(lines_str: str, default_country: str = "US") -> PartyIdentificationRecord:
        lines = [ln.strip() for ln in lines_str.splitlines() if ln.strip()]
        if not lines:
            return PartyIdentificationRecord(
                name="",
                account_id="",
                iban_or_bban="",
                postal_address=PostalAddressRecord(country=default_country),
            )
        acct = ""
        name = ""
        addr_lines: List[str] = []
        if lines[0].startswith("/"):
            acct = lines[0].lstrip("/").strip()
            name = lines[1] if len(lines) > 1 else ""
            addr_lines = lines[2:]
        else:
            name = lines[0]
            addr_lines = lines[1:]

        country = default_country
        if acct and len(acct) >= 15 and acct[:2].isalpha():
            country = acct[:2].upper()
        for al in addr_lines:
            tokens = [t.strip(",") for t in al.split()]
            if tokens and len(tokens[-1]) == 2 and tokens[-1].isalpha():
                country = tokens[-1].upper()

        return PartyIdentificationRecord(
            name=name,
            account_id=acct,
            iban_or_bban=acct,
            postal_address=PostalAddressRecord(
                town_name=addr_lines[0] if addr_lines else None,
                country=country,
                address_lines=addr_lines,
            ),
        )

    @classmethod
    def parse_mt_message(cls, raw_mt: str) -> ParsedWireTransferMessage:
        if not raw_mt or ":20:" not in raw_mt:
            raise ValidationError("Invalid SWIFT MT message: missing mandatory :20: reference field.")

        raw_digest = hashlib.sha256(raw_mt.strip().encode("utf-8")).hexdigest()
        msg_type, fields = cls._extract_block4_fields(raw_mt)

        ref_20 = fields.get("20", ["UNKNOWN-REF"])[0]
        field_32a = fields.get("32A", ["261012USD1000,00"])[0]
        iso_date, ccy, raw_amt = cls._parse_32a(field_32a)
        usd_amt = round(raw_amt * FX_RATES_TO_USD.get(ccy, 1.0), 2)

        raw_50 = (
            fields.get("50K", [None])[0]
            or fields.get("50F", [None])[0]
            or fields.get("50A", [None])[0]
            or ""
        )
        raw_59 = (
            fields.get("59", [None])[0]
            or fields.get("59A", [None])[0]
            or fields.get("58A", [None])[0]
            or ""
        )

        debtor = cls._parse_party_block(raw_50, default_country="US")
        creditor = cls._parse_party_block(raw_59, default_country="US")

        agents: List[AgentInstitutionRecord] = []
        for tag, role in (("52A", "ORDERING_INSTITUTION"), ("53A", "SENDERS_CORRESPONDENT"), ("56A", "INTERMEDIARY"), ("57A", "ACCOUNT_WITH_INSTITUTION")):
            if tag in fields:
                bic = fields[tag][0].splitlines()[-1].strip()
                ctry = bic[4:6] if len(bic) >= 6 else "US"
                agents.append(AgentInstitutionRecord(bic=bic, country_code=ctry, role=role))

        remit_70 = fields.get("70", [""])[0].replace("\n", " ")
        sender_to_rec_72 = fields.get("72", [""])[0].replace("\n", " ")
        combined_remit = f"{remit_70} {sender_to_rec_72}".strip()
        chrg = fields.get("71A", ["SHA"])[0]

        msg = ParsedWireTransferMessage(
            message_id=ref_20,
            message_standard=f"SWIFT_{msg_type}",
            creation_timestamp=f"{iso_date}T12:00:00+00:00",
            end_to_end_id=ref_20,
            uetr=str(uuid.uuid4()),
            instructed_amount=raw_amt,
            instructed_currency=ccy,
            interbank_settlement_amount_usd=usd_amt,
            settlement_date=iso_date,
            charge_bearer=chrg,
            debtor=debtor,
            creditor=creditor,
            agents=agents,
            remittance_unstructured=combined_remit,
            raw_digest_sha256=raw_digest,
        )
        audit = Iso20022MxParser.audit_travel_rule(msg)
        if "/INS/" in sender_to_rec_72 or "DO NOT MENTION" in sender_to_rec_72.upper() or "RESEND WITHOUT" in sender_to_rec_72.upper():
            audit.intermediary_stripping_indicators.append("FIELD_72_SANCTIONS_CIRCUMVENTION_INSTRUCTION")
            audit.is_compliant = False
            audit.risk_score_penalty = min(100.0, audit.risk_score_penalty + 45.0)
        msg.travel_rule_audit = audit
        return msg

    @staticmethod
    def build_sample_mt103(
        ref_20: str = "MT103-2026-8821",
        date_yymmdd: str = "261014",
        currency: str = "USD",
        amount: float = 37500.00,
        ordering_customer_50k: str = "/VG88BVI00019283\nBALTIC HORIZON TRADING LTD\nROAD TOWN TORTOLA VG",
        beneficiary_59: str = "/IR99TEHRAN009182\nCASPIAN MERIDIAN PETROCHEM\nTEHRAN IR",
        remittance_70: str = "INVOICE 99412 PETROCHEMICAL TURBINE VALVES",
        field_72: str = "/ACC/DO NOT MENTION IRAN ORIGIN IN USD CLEARING",
    ) -> str:
        amt_str = f"{amount:.2f}".replace(".", ",")
        return (
            "{1:F01BVIOVGVGAXXX0000000000}{2:I103ETBKAEADXXXXN}{4:\n"
            f":20:{ref_20}\n"
            ":23B:CRED\n"
            f":32A:{date_yymmdd}{currency}{amt_str}\n"
            f":50K:{ordering_customer_50k}\n"
            ":52A:BVIOVGVGXXX\n"
            ":56A:ETBKAEADXXX\n"
            ":57A:TTBKIRTHXXX\n"
            f":59:{beneficiary_59}\n"
            f":70:{remittance_70}\n"
            ":71A:OUR\n"
            f":72:{field_72}\n"
            "-}"
        )
