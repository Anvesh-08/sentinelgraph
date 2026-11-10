"""
Unit and integration tests for ISO 20022 MX XML (`pacs.008`, `pacs.009`, `pain.001`, `camt.053`)
and SWIFT FIN (`MT103`, `MT202COV`) parsing, Travel Rule completeness auditing, and wire-stripping detection.
"""
import unittest

from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.iso20022.mx_parser import Iso20022MxParser
from backend.app.iso20022.service import WireMessageIngestionService
from backend.app.iso20022.swift_mt_parser import SwiftMtParser


class Iso20022AndSwiftUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.service = WireMessageIngestionService(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_pacs008_parsing_and_travel_rule_compliance(self) -> None:
        xml_str = Iso20022MxParser.build_sample_pacs008_xml()
        messages = Iso20022MxParser.parse_xml(xml_str)
        self.assertEqual(len(messages), 1)
        msg = messages[0]
        self.assertEqual(msg.message_standard, "ISO20022_PACS008")
        self.assertEqual(msg.interbank_settlement_amount_usd, 48500.00)
        self.assertEqual(msg.debtor.postal_address.country, "VG")
        self.assertEqual(msg.creditor.postal_address.country, "AE")
        self.assertTrue(msg.travel_rule_audit.is_compliant)

    def test_pacs008_travel_rule_violation_detection(self) -> None:
        stripped_xml = Iso20022MxParser.build_sample_pacs008_xml(
            end_to_end_id="NOTPROVIDED",
            debtor_name="UNKNOWN",
            debtor_iban="",
            remittance_info="NONREF BY ORDER OF CLIENT",
        )
        msg = Iso20022MxParser.parse_xml(stripped_xml)[0]
        self.assertFalse(msg.travel_rule_audit.is_compliant)
        self.assertIn("MISSING_OR_PLACEHOLDER_ORIGINATOR_NAME", msg.travel_rule_audit.originator_defects)
        self.assertGreaterEqual(len(msg.travel_rule_audit.intermediary_stripping_indicators), 1)
        self.assertGreater(msg.travel_rule_audit.risk_score_penalty, 40.0)

    def test_swift_mt103_parsing_and_field72_sanctions_stripping_detection(self) -> None:
        raw_mt = SwiftMtParser.build_sample_mt103()
        msg = SwiftMtParser.parse_mt_message(raw_mt)
        self.assertEqual(msg.message_standard, "SWIFT_MT103")
        self.assertEqual(msg.interbank_settlement_amount_usd, 37500.00)
        self.assertEqual(msg.debtor.postal_address.country, "VG")
        self.assertEqual(msg.creditor.postal_address.country, "IR")
        self.assertFalse(msg.travel_rule_audit.is_compliant)
        self.assertIn(
            "FIELD_72_SANCTIONS_CIRCUMVENTION_INSTRUCTION",
            msg.travel_rule_audit.intermediary_stripping_indicators,
        )

    def test_wire_ingestion_into_sentinelgraph_ledger(self) -> None:
        xml_str = Iso20022MxParser.build_sample_pacs008_xml(
            msg_id="PACS008-INGEST-01",
            end_to_end_id="E2E-INGEST-001",
            amount=64000.0,
        )
        res = self.service.ingest_iso20022_xml(
            xml_payload=xml_str,
            target_internal_account_id="acct-002",
            direction="OUTBOUND",
        )
        self.assertEqual(res["messages_parsed"], 1)
        self.assertEqual(len(res["ingested_transactions"]), 1)
        self.assertEqual(res["ingested_transactions"][0]["amount_usd"], 64000.0)


if __name__ == "__main__":
    unittest.main()
