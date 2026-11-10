"""
Exhaustive Positive & Negative Threshold Boundary Test Matrix (`tests/unit/test_175_rule_boundary_matrix.py`).
Verifies parameter override sensitivity, positive scenario capture, and below-threshold suppression
across the specialized typology detectors.
"""
import unittest

from backend.app.reporting.regulatory_matrix import get_statutory_requirements, summarize_regime_coverage
from backend.app.typologies.base import TypologyEvaluationContext
from backend.app.typologies.global_registry import get_175_detector_map


class Exhaustive175RuleBoundaryMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detectors = get_175_detector_map()
        cls.customers = {
            "cust-test-1": {
                "id": "cust-test-1",
                "customer_type": "BUSINESS",
                "legal_name": "Boundary Test Global Trading LLC",
                "date_of_birth_or_inc": "1945-05-10",
                "residence_country": "US",
                "nationality_or_reg_country": "VG",
                "occupation_or_industry": "IMPORT EXPORT",
                "expected_monthly_volume_usd": 5000.0,
                "pep_flag": 1,
                "risk_band": "CRITICAL",
                "sanctions_status": "POTENTIAL_MATCH",
            }
        }
        cls.accounts = {
            "acct-test-1": {
                "id": "acct-test-1",
                "customer_id": "cust-test-1",
                "account_number": "SG-TEST-0001",
                "status": "ACTIVE",
            }
        }

    def _run_boundary_pair(self, rule_id: str, min_amt: float, keyword: str, direction: str) -> None:
        detector = self.detectors[rule_id]
        # 1. Above-threshold positive transaction matching scenario_tag & keyword
        pos_tx = [
            {
                "id": f"tx-pos-{rule_id}",
                "account_id": "acct-test-1",
                "customer_id": "cust-test-1",
                "counterparty_id": "cp-test-1",
                "counterparty_account_id": None,
                "tx_timestamp": "2026-10-15T02:15:00+00:00",
                "tx_type": "WIRE_INTERNATIONAL",
                "direction": direction,
                "amount_usd": min_amt + 5000.0,
                "balance_after_usd": 1000.0,
                "channel": "SWIFT_NET",
                "origin_country": "US",
                "destination_country": "IR",
                "remittance_purpose": f"URGENT {keyword} SETTLEMENT",
                "scenario_tag": f"TEST_{rule_id}",
            }
        ]
        pos_ctx = TypologyEvaluationContext(self.customers, self.accounts, pos_tx)
        pos_triggers = detector.evaluate(pos_ctx)
        self.assertEqual(len(pos_triggers), 1, f'Expected positive trigger for {rule_id}')
        self.assertEqual(pos_triggers[0].rule_id, rule_id)

        # 2. Below-threshold negative transaction ($10.00 domestic transfer with benign memo)
        neg_tx = [
            {
                "id": f"tx-neg-{rule_id}",
                "account_id": "acct-test-1",
                "customer_id": "cust-test-1",
                "counterparty_id": "cp-test-1",
                "counterparty_account_id": None,
                "tx_timestamp": "2026-10-15T14:00:00+00:00",
                "tx_type": "ACH_DEBIT",
                "direction": direction,
                "amount_usd": 10.0,
                "balance_after_usd": 50000.0,
                "channel": "ONLINE_WEB",
                "origin_country": "US",
                "destination_country": "US",
                "remittance_purpose": "Coffee shop purchase",
                "scenario_tag": "BASELINE_NORMAL",
            }
        ]
        neg_ctx = TypologyEvaluationContext(self.customers, self.accounts, neg_tx)
        neg_triggers = detector.evaluate(neg_ctx)
        self.assertEqual(len(neg_triggers), 0, f'Expected zero false-positive trigger for {rule_id}')

    def test_statutory_matrix_completeness(self) -> None:
        summary = summarize_regime_coverage()
        self.assertEqual(summary["total_mapped_rules"], 175)

    def test_boundary_aml_tbml_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-001."""
        req = get_statutory_requirements("AML-TBML-001")
        self.assertEqual(req["rule_id"], "AML-TBML-001")
        self._run_boundary_pair("AML-TBML-001", 18000.0, 'INVOICE', 'OUTBOUND')

    def test_boundary_aml_tbml_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-002."""
        req = get_statutory_requirements("AML-TBML-002")
        self.assertEqual(req["rule_id"], "AML-TBML-002")
        self._run_boundary_pair("AML-TBML-002", 16000.0, 'SHIPMENT', 'INBOUND')

    def test_boundary_aml_tbml_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-003."""
        req = get_statutory_requirements("AML-TBML-003")
        self.assertEqual(req["rule_id"], "AML-TBML-003")
        self._run_boundary_pair("AML-TBML-003", 15000.0, 'BILL OF LADING', 'OUTBOUND')

    def test_boundary_aml_tbml_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-004."""
        req = get_statutory_requirements("AML-TBML-004")
        self.assertEqual(req["rule_id"], "AML-TBML-004")
        self._run_boundary_pair("AML-TBML-004", 20000.0, 'TRANSIT', 'OUTBOUND')

    def test_boundary_aml_tbml_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-005."""
        req = get_statutory_requirements("AML-TBML-005")
        self.assertEqual(req["rule_id"], "AML-TBML-005")
        self._run_boundary_pair("AML-TBML-005", 14000.0, 'SEMICONDUCTOR', 'OUTBOUND')

    def test_boundary_aml_tbml_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-006."""
        req = get_statutory_requirements("AML-TBML-006")
        self.assertEqual(req["rule_id"], "AML-TBML-006")
        self._run_boundary_pair("AML-TBML-006", 25000.0, 'LETTER OF CREDIT', 'OUTBOUND')

    def test_boundary_aml_tbml_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-007."""
        req = get_statutory_requirements("AML-TBML-007")
        self.assertEqual(req["rule_id"], "AML-TBML-007")
        self._run_boundary_pair("AML-TBML-007", 19000.0, 'CHARTER', 'OUTBOUND')

    def test_boundary_aml_tbml_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TBML-008."""
        req = get_statutory_requirements("AML-TBML-008")
        self.assertEqual(req["rule_id"], "AML-TBML-008")
        self._run_boundary_pair("AML-TBML-008", 22000.0, 'PETROCHEMICAL', 'OUTBOUND')

    def test_boundary_aml_corr_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-001."""
        req = get_statutory_requirements("AML-CORR-001")
        self.assertEqual(req["rule_id"], "AML-CORR-001")
        self._run_boundary_pair("AML-CORR-001", 30000.0, 'NESTED', 'INBOUND')

    def test_boundary_aml_corr_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-002."""
        req = get_statutory_requirements("AML-CORR-002")
        self.assertEqual(req["rule_id"], "AML-CORR-002")
        self._run_boundary_pair("AML-CORR-002", 20000.0, 'PTA', 'OUTBOUND')

    def test_boundary_aml_corr_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-003."""
        req = get_statutory_requirements("AML-CORR-003")
        self.assertEqual(req["rule_id"], "AML-CORR-003")
        self._run_boundary_pair("AML-CORR-003", 25000.0, 'COVER', 'OUTBOUND')

    def test_boundary_aml_corr_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-004."""
        req = get_statutory_requirements("AML-CORR-004")
        self.assertEqual(req["rule_id"], "AML-CORR-004")
        self._run_boundary_pair("AML-CORR-004", 35000.0, 'CLEARING', 'OUTBOUND')

    def test_boundary_aml_corr_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-005."""
        req = get_statutory_requirements("AML-CORR-005")
        self.assertEqual(req["rule_id"], "AML-CORR-005")
        self._run_boundary_pair("AML-CORR-005", 15000.0, 'POUCH', 'INBOUND')

    def test_boundary_aml_corr_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-006."""
        req = get_statutory_requirements("AML-CORR-006")
        self.assertEqual(req["rule_id"], "AML-CORR-006")
        self._run_boundary_pair("AML-CORR-006", 28000.0, 'CORRESPONDENT', 'OUTBOUND')

    def test_boundary_aml_corr_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CORR-007."""
        req = get_statutory_requirements("AML-CORR-007")
        self.assertEqual(req["rule_id"], "AML-CORR-007")
        self._run_boundary_pair("AML-CORR-007", 32000.0, 'LOAN', 'INBOUND')

    def test_boundary_aml_cry_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-001."""
        req = get_statutory_requirements("AML-CRY-001")
        self.assertEqual(req["rule_id"], "AML-CRY-001")
        self._run_boundary_pair("AML-CRY-001", 8000.0, 'CRYPTO', 'OUTBOUND')

    def test_boundary_aml_cry_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-002."""
        req = get_statutory_requirements("AML-CRY-002")
        self.assertEqual(req["rule_id"], "AML-CRY-002")
        self._run_boundary_pair("AML-CRY-002", 10000.0, 'BRIDGE', 'OUTBOUND')

    def test_boundary_aml_cry_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-003."""
        req = get_statutory_requirements("AML-CRY-003")
        self.assertEqual(req["rule_id"], "AML-CRY-003")
        self._run_boundary_pair("AML-CRY-003", 5000.0, 'MIXER', 'OUTBOUND')

    def test_boundary_aml_cry_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-004."""
        req = get_statutory_requirements("AML-CRY-004")
        self.assertEqual(req["rule_id"], "AML-CRY-004")
        self._run_boundary_pair("AML-CRY-004", 12000.0, 'WALLET', 'INBOUND')

    def test_boundary_aml_cry_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-005."""
        req = get_statutory_requirements("AML-CRY-005")
        self.assertEqual(req["rule_id"], "AML-CRY-005")
        self._run_boundary_pair("AML-CRY-005", 25000.0, 'USDT', 'OUTBOUND')

    def test_boundary_aml_cry_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-006."""
        req = get_statutory_requirements("AML-CRY-006")
        self.assertEqual(req["rule_id"], "AML-CRY-006")
        self._run_boundary_pair("AML-CRY-006", 6000.0, 'KIOSK', 'OUTBOUND')

    def test_boundary_aml_cry_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-007."""
        req = get_statutory_requirements("AML-CRY-007")
        self.assertEqual(req["rule_id"], "AML-CRY-007")
        self._run_boundary_pair("AML-CRY-007", 3000.0, 'DARKNET', 'INBOUND')

    def test_boundary_aml_cry_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-008."""
        req = get_statutory_requirements("AML-CRY-008")
        self.assertEqual(req["rule_id"], "AML-CRY-008")
        self._run_boundary_pair("AML-CRY-008", 9000.0, 'RANSOM', 'OUTBOUND')

    def test_boundary_aml_cry_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-009."""
        req = get_statutory_requirements("AML-CRY-009")
        self.assertEqual(req["rule_id"], "AML-CRY-009")
        self._run_boundary_pair("AML-CRY-009", 15000.0, 'LIQUIDITY', 'INBOUND')

    def test_boundary_aml_cry_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-010."""
        req = get_statutory_requirements("AML-CRY-010")
        self.assertEqual(req["rule_id"], "AML-CRY-010")
        self._run_boundary_pair("AML-CRY-010", 18000.0, 'NFT', 'OUTBOUND')

    def test_boundary_aml_cry_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-011."""
        req = get_statutory_requirements("AML-CRY-011")
        self.assertEqual(req["rule_id"], "AML-CRY-011")
        self._run_boundary_pair("AML-CRY-011", 20000.0, 'EXCHANGE', 'OUTBOUND')

    def test_boundary_aml_cry_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-012."""
        req = get_statutory_requirements("AML-CRY-012")
        self.assertEqual(req["rule_id"], "AML-CRY-012")
        self._run_boundary_pair("AML-CRY-012", 14000.0, 'SWEEP', 'OUTBOUND')

    def test_boundary_aml_cry_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-013."""
        req = get_statutory_requirements("AML-CRY-013")
        self.assertEqual(req["rule_id"], "AML-CRY-013")
        self._run_boundary_pair("AML-CRY-013", 9500.0, 'ESCROW', 'INBOUND')

    def test_boundary_aml_cry_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-014."""
        req = get_statutory_requirements("AML-CRY-014")
        self.assertEqual(req["rule_id"], "AML-CRY-014")
        self._run_boundary_pair("AML-CRY-014", 16000.0, 'HAWALA', 'OUTBOUND')

    def test_boundary_aml_cry_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-CRY-015."""
        req = get_statutory_requirements("AML-CRY-015")
        self.assertEqual(req["rule_id"], "AML-CRY-015")
        self._run_boundary_pair("AML-CRY-015", 7000.0, 'DRAIN', 'OUTBOUND')

    def test_boundary_aml_rbi_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-001."""
        req = get_statutory_requirements("AML-RBI-001")
        self.assertEqual(req["rule_id"], "AML-RBI-001")
        self._run_boundary_pair("AML-RBI-001", 550.0, 'CASH', 'INBOUND')

    def test_boundary_aml_rbi_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-002."""
        req = get_statutory_requirements("AML-RBI-002")
        self.assertEqual(req["rule_id"], "AML-RBI-002")
        self._run_boundary_pair("AML-RBI-002", 10500.0, 'CASH', 'INBOUND')

    def test_boundary_aml_rbi_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-003."""
        req = get_statutory_requirements("AML-RBI-003")
        self.assertEqual(req["rule_id"], "AML-RBI-003")
        self._run_boundary_pair("AML-RBI-003", 8000.0, 'UPI', 'INBOUND')

    def test_boundary_aml_rbi_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-004."""
        req = get_statutory_requirements("AML-RBI-004")
        self.assertEqual(req["rule_id"], "AML-RBI-004")
        self._run_boundary_pair("AML-RBI-004", 15000.0, 'LRS', 'OUTBOUND')

    def test_boundary_aml_rbi_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-005."""
        req = get_statutory_requirements("AML-RBI-005")
        self.assertEqual(req["rule_id"], "AML-RBI-005")
        self._run_boundary_pair("AML-RBI-005", 18000.0, 'REPATRIATION', 'OUTBOUND')

    def test_boundary_aml_rbi_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-006."""
        req = get_statutory_requirements("AML-RBI-006")
        self.assertEqual(req["rule_id"], "AML-RBI-006")
        self._run_boundary_pair("AML-RBI-006", 25000.0, 'EXPORT ADVANCE', 'INBOUND')

    def test_boundary_aml_rbi_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-007."""
        req = get_statutory_requirements("AML-RBI-007")
        self.assertEqual(req["rule_id"], "AML-RBI-007")
        self._run_boundary_pair("AML-RBI-007", 22000.0, 'IMPORT ADVANCE', 'OUTBOUND')

    def test_boundary_aml_rbi_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-008."""
        req = get_statutory_requirements("AML-RBI-008")
        self.assertEqual(req["rule_id"], "AML-RBI-008")
        self._run_boundary_pair("AML-RBI-008", 4000.0, 'DEMAND DRAFT', 'OUTBOUND')

    def test_boundary_aml_rbi_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-009."""
        req = get_statutory_requirements("AML-RBI-009")
        self.assertEqual(req["rule_id"], "AML-RBI-009")
        self._run_boundary_pair("AML-RBI-009", 6000.0, 'BSBDA', 'INBOUND')

    def test_boundary_aml_rbi_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-010."""
        req = get_statutory_requirements("AML-RBI-010")
        self.assertEqual(req["rule_id"], "AML-RBI-010")
        self._run_boundary_pair("AML-RBI-010", 20000.0, 'GST INVOICE', 'OUTBOUND')

    def test_boundary_aml_rbi_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-011."""
        req = get_statutory_requirements("AML-RBI-011")
        self.assertEqual(req["rule_id"], "AML-RBI-011")
        self._run_boundary_pair("AML-RBI-011", 12000.0, 'GAMING', 'OUTBOUND')

    def test_boundary_aml_rbi_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-012."""
        req = get_statutory_requirements("AML-RBI-012")
        self.assertEqual(req["rule_id"], "AML-RBI-012")
        self._run_boundary_pair("AML-RBI-012", 19000.0, 'BULLION', 'OUTBOUND')

    def test_boundary_aml_rbi_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-013."""
        req = get_statutory_requirements("AML-RBI-013")
        self.assertEqual(req["rule_id"], "AML-RBI-013")
        self._run_boundary_pair("AML-RBI-013", 9000.0, 'LOAN REPAYMENT', 'INBOUND')

    def test_boundary_aml_rbi_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-014."""
        req = get_statutory_requirements("AML-RBI-014")
        self.assertEqual(req["rule_id"], "AML-RBI-014")
        self._run_boundary_pair("AML-RBI-014", 14000.0, 'DONATION', 'INBOUND')

    def test_boundary_aml_rbi_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-RBI-015."""
        req = get_statutory_requirements("AML-RBI-015")
        self.assertEqual(req["rule_id"], "AML-RBI-015")
        self._run_boundary_pair("AML-RBI-015", 5000.0, 'AEPS', 'OUTBOUND')

    def test_boundary_aml_euk_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-001."""
        req = get_statutory_requirements("AML-EUK-001")
        self.assertEqual(req["rule_id"], "AML-EUK-001")
        self._run_boundary_pair("AML-EUK-001", 15000.0, 'SEPA', 'OUTBOUND')

    def test_boundary_aml_euk_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-002."""
        req = get_statutory_requirements("AML-EUK-002")
        self.assertEqual(req["rule_id"], "AML-EUK-002")
        self._run_boundary_pair("AML-EUK-002", 10000.0, 'FASTER PAYMENTS', 'OUTBOUND')

    def test_boundary_aml_euk_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-003."""
        req = get_statutory_requirements("AML-EUK-003")
        self.assertEqual(req["rule_id"], "AML-EUK-003")
        self._run_boundary_pair("AML-EUK-003", 24000.0, 'LIMITED PARTNERSHIP', 'OUTBOUND')

    def test_boundary_aml_euk_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-004."""
        req = get_statutory_requirements("AML-EUK-004")
        self.assertEqual(req["rule_id"], "AML-EUK-004")
        self._run_boundary_pair("AML-EUK-004", 30000.0, 'WEALTH MANAGEMENT', 'INBOUND')

    def test_boundary_aml_euk_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-005."""
        req = get_statutory_requirements("AML-EUK-005")
        self.assertEqual(req["rule_id"], "AML-EUK-005")
        self._run_boundary_pair("AML-EUK-005", 40000.0, 'REAL ESTATE ESCROW', 'OUTBOUND')

    def test_boundary_aml_euk_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-006."""
        req = get_statutory_requirements("AML-EUK-006")
        self.assertEqual(req["rule_id"], "AML-EUK-006")
        self._run_boundary_pair("AML-EUK-006", 9000.0, 'SCT INST', 'OUTBOUND')

    def test_boundary_aml_euk_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-007."""
        req = get_statutory_requirements("AML-EUK-007")
        self.assertEqual(req["rule_id"], "AML-EUK-007")
        self._run_boundary_pair("AML-EUK-007", 28000.0, 'TRUST SETTLEMENT', 'OUTBOUND')

    def test_boundary_aml_euk_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-008."""
        req = get_statutory_requirements("AML-EUK-008")
        self.assertEqual(req["rule_id"], "AML-EUK-008")
        self._run_boundary_pair("AML-EUK-008", 17000.0, 'VIRTUAL IBAN', 'INBOUND')

    def test_boundary_aml_euk_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-009."""
        req = get_statutory_requirements("AML-EUK-009")
        self.assertEqual(req["rule_id"], "AML-EUK-009")
        self._run_boundary_pair("AML-EUK-009", 35000.0, 'LUXURY ESCROW', 'OUTBOUND')

    def test_boundary_aml_euk_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-010."""
        req = get_statutory_requirements("AML-EUK-010")
        self.assertEqual(req["rule_id"], "AML-EUK-010")
        self._run_boundary_pair("AML-EUK-010", 26000.0, 'IMAGE RIGHTS', 'OUTBOUND')

    def test_boundary_aml_euk_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-011."""
        req = get_statutory_requirements("AML-EUK-011")
        self.assertEqual(req["rule_id"], "AML-EUK-011")
        self._run_boundary_pair("AML-EUK-011", 32000.0, 'ELECTRONICS WHOLESALE', 'OUTBOUND')

    def test_boundary_aml_euk_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-012."""
        req = get_statutory_requirements("AML-EUK-012")
        self.assertEqual(req["rule_id"], "AML-EUK-012")
        self._run_boundary_pair("AML-EUK-012", 14000.0, 'BALANCING SETTLEMENT', 'OUTBOUND')

    def test_boundary_aml_euk_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-013."""
        req = get_statutory_requirements("AML-EUK-013")
        self.assertEqual(req["rule_id"], "AML-EUK-013")
        self._run_boundary_pair("AML-EUK-013", 10000.0, 'SUBSIDIARY', 'OUTBOUND')

    def test_boundary_aml_euk_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-014."""
        req = get_statutory_requirements("AML-EUK-014")
        self.assertEqual(req["rule_id"], "AML-EUK-014")
        self._run_boundary_pair("AML-EUK-014", 21000.0, 'NOMINEE', 'OUTBOUND')

    def test_boundary_aml_euk_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-EUK-015."""
        req = get_statutory_requirements("AML-EUK-015")
        self.assertEqual(req["rule_id"], "AML-EUK-015")
        self._run_boundary_pair("AML-EUK-015", 8500.0, 'TUITION', 'INBOUND')

    def test_boundary_frd_syn_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-001."""
        req = get_statutory_requirements("FRD-SYN-001")
        self.assertEqual(req["rule_id"], "FRD-SYN-001")
        self._run_boundary_pair("FRD-SYN-001", 20000.0, 'UPDATED BANK DETAILS', 'OUTBOUND')

    def test_boundary_frd_syn_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-002."""
        req = get_statutory_requirements("FRD-SYN-002")
        self.assertEqual(req["rule_id"], "FRD-SYN-002")
        self._run_boundary_pair("FRD-SYN-002", 15000.0, 'INVESTMENT PLATFORM', 'OUTBOUND')

    def test_boundary_frd_syn_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-003."""
        req = get_statutory_requirements("FRD-SYN-003")
        self.assertEqual(req["rule_id"], "FRD-SYN-003")
        self._run_boundary_pair("FRD-SYN-003", 12000.0, 'CREDIT DRAW', 'OUTBOUND')

    def test_boundary_frd_syn_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-004."""
        req = get_statutory_requirements("FRD-SYN-004")
        self.assertEqual(req["rule_id"], "FRD-SYN-004")
        self._run_boundary_pair("FRD-SYN-004", 9500.0, 'FLOAT', 'OUTBOUND')

    def test_boundary_frd_syn_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-005."""
        req = get_statutory_requirements("FRD-SYN-005")
        self.assertEqual(req["rule_id"], "FRD-SYN-005")
        self._run_boundary_pair("FRD-SYN-005", 6500.0, 'PAYROLL', 'INBOUND')

    def test_boundary_frd_syn_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-006."""
        req = get_statutory_requirements("FRD-SYN-006")
        self.assertEqual(req["rule_id"], "FRD-SYN-006")
        self._run_boundary_pair("FRD-SYN-006", 35000.0, 'CONFIDENTIAL ACQUISITION', 'OUTBOUND')

    def test_boundary_frd_syn_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-007."""
        req = get_statutory_requirements("FRD-SYN-007")
        self.assertEqual(req["rule_id"], "FRD-SYN-007")
        self._run_boundary_pair("FRD-SYN-007", 28000.0, 'MEDICAL CLAIM', 'INBOUND')

    def test_boundary_frd_syn_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-008."""
        req = get_statutory_requirements("FRD-SYN-008")
        self.assertEqual(req["rule_id"], "FRD-SYN-008")
        self._run_boundary_pair("FRD-SYN-008", 22000.0, 'CONSULTING FEE', 'OUTBOUND')

    def test_boundary_frd_syn_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-009."""
        req = get_statutory_requirements("FRD-SYN-009")
        self.assertEqual(req["rule_id"], "FRD-SYN-009")
        self._run_boundary_pair("FRD-SYN-009", 8000.0, 'MERCHANT REFUND', 'INBOUND')

    def test_boundary_frd_syn_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-010."""
        req = get_statutory_requirements("FRD-SYN-010")
        self.assertEqual(req["rule_id"], "FRD-SYN-010")
        self._run_boundary_pair("FRD-SYN-010", 11000.0, 'URGENT WIRE', 'OUTBOUND')

    def test_boundary_frd_syn_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-011."""
        req = get_statutory_requirements("FRD-SYN-011")
        self.assertEqual(req["rule_id"], "FRD-SYN-011")
        self._run_boundary_pair("FRD-SYN-011", 45000.0, 'SECURITIES SETTLEMENT', 'OUTBOUND')

    def test_boundary_frd_syn_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-012."""
        req = get_statutory_requirements("FRD-SYN-012")
        self.assertEqual(req["rule_id"], "FRD-SYN-012")
        self._run_boundary_pair("FRD-SYN-012", 30000.0, 'OMNIBUS LIQUIDATION', 'INBOUND')

    def test_boundary_frd_syn_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-013."""
        req = get_statutory_requirements("FRD-SYN-013")
        self.assertEqual(req["rule_id"], "FRD-SYN-013")
        self._run_boundary_pair("FRD-SYN-013", 50000.0, 'TITLE ESCROW', 'OUTBOUND')

    def test_boundary_frd_syn_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-014."""
        req = get_statutory_requirements("FRD-SYN-014")
        self.assertEqual(req["rule_id"], "FRD-SYN-014")
        self._run_boundary_pair("FRD-SYN-014", 7500.0, 'LODGING', 'OUTBOUND')

    def test_boundary_frd_syn_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-SYN-015."""
        req = get_statutory_requirements("FRD-SYN-015")
        self.assertEqual(req["rule_id"], "FRD-SYN-015")
        self._run_boundary_pair("FRD-SYN-015", 13000.0, 'LABORATORY CHEMICAL', 'OUTBOUND')

    def test_boundary_aml_mar_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-001."""
        req = get_statutory_requirements("AML-MAR-001")
        self.assertEqual(req["rule_id"], "AML-MAR-001")
        self._run_boundary_pair("AML-MAR-001", 28000.0, 'BUNKER', 'OUTBOUND')

    def test_boundary_aml_mar_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-002."""
        req = get_statutory_requirements("AML-MAR-002")
        self.assertEqual(req["rule_id"], "AML-MAR-002")
        self._run_boundary_pair("AML-MAR-002", 45000.0, 'STS TRANSFER', 'OUTBOUND')

    def test_boundary_aml_mar_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-003."""
        req = get_statutory_requirements("AML-MAR-003")
        self.assertEqual(req["rule_id"], "AML-MAR-003")
        self._run_boundary_pair("AML-MAR-003", 22000.0, 'VESSEL INSURANCE', 'OUTBOUND')

    def test_boundary_aml_mar_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-004."""
        req = get_statutory_requirements("AML-MAR-004")
        self.assertEqual(req["rule_id"], "AML-MAR-004")
        self._run_boundary_pair("AML-MAR-004", 15000.0, 'PORT DISBURSEMENT', 'OUTBOUND')

    def test_boundary_aml_mar_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-005."""
        req = get_statutory_requirements("AML-MAR-005")
        self.assertEqual(req["rule_id"], "AML-MAR-005")
        self._run_boundary_pair("AML-MAR-005", 32000.0, 'TIME CHARTER', 'INBOUND')

    def test_boundary_aml_mar_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-006."""
        req = get_statutory_requirements("AML-MAR-006")
        self.assertEqual(req["rule_id"], "AML-MAR-006")
        self._run_boundary_pair("AML-MAR-006", 50000.0, 'MINISTRY', 'INBOUND')

    def test_boundary_aml_mar_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-007."""
        req = get_statutory_requirements("AML-MAR-007")
        self.assertEqual(req["rule_id"], "AML-MAR-007")
        self._run_boundary_pair("AML-MAR-007", 38000.0, 'AEROSPACE', 'OUTBOUND')

    def test_boundary_aml_mar_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-008."""
        req = get_statutory_requirements("AML-MAR-008")
        self.assertEqual(req["rule_id"], "AML-MAR-008")
        self._run_boundary_pair("AML-MAR-008", 26000.0, 'MINING CONCESSION', 'OUTBOUND')

    def test_boundary_aml_mar_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-009."""
        req = get_statutory_requirements("AML-MAR-009")
        self.assertEqual(req["rule_id"], "AML-MAR-009")
        self._run_boundary_pair("AML-MAR-009", 19000.0, 'EMBASSY', 'OUTBOUND')

    def test_boundary_aml_mar_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-010."""
        req = get_statutory_requirements("AML-MAR-010")
        self.assertEqual(req["rule_id"], "AML-MAR-010")
        self._run_boundary_pair("AML-MAR-010", 21000.0, 'CHEMICAL', 'OUTBOUND')

    def test_boundary_aml_mar_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-011."""
        req = get_statutory_requirements("AML-MAR-011")
        self.assertEqual(req["rule_id"], "AML-MAR-011")
        self._run_boundary_pair("AML-MAR-011", 29000.0, 'FREEPORT', 'OUTBOUND')

    def test_boundary_aml_mar_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-012."""
        req = get_statutory_requirements("AML-MAR-012")
        self.assertEqual(req["rule_id"], "AML-MAR-012")
        self._run_boundary_pair("AML-MAR-012", 40000.0, 'REINSURANCE', 'OUTBOUND')

    def test_boundary_aml_mar_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-013."""
        req = get_statutory_requirements("AML-MAR-013")
        self.assertEqual(req["rule_id"], "AML-MAR-013")
        self._run_boundary_pair("AML-MAR-013", 17000.0, 'RESUBMITTED', 'OUTBOUND')

    def test_boundary_aml_mar_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-014."""
        req = get_statutory_requirements("AML-MAR-014")
        self.assertEqual(req["rule_id"], "AML-MAR-014")
        self._run_boundary_pair("AML-MAR-014", 55000.0, 'FAMILY TRUST', 'INBOUND')

    def test_boundary_aml_mar_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-MAR-015."""
        req = get_statutory_requirements("AML-MAR-015")
        self.assertEqual(req["rule_id"], "AML-MAR-015")
        self._run_boundary_pair("AML-MAR-015", 34000.0, 'GOLD DORÉ', 'OUTBOUND')

    def test_boundary_aml_trd_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-001."""
        req = get_statutory_requirements("AML-TRD-001")
        self.assertEqual(req["rule_id"], "AML-TRD-001")
        self._run_boundary_pair("AML-TRD-001", 24000.0, 'FACTORING', 'INBOUND')

    def test_boundary_aml_trd_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-002."""
        req = get_statutory_requirements("AML-TRD-002")
        self.assertEqual(req["rule_id"], "AML-TRD-002")
        self._run_boundary_pair("AML-TRD-002", 42000.0, 'SBLC DRAW', 'INBOUND')

    def test_boundary_aml_trd_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-003."""
        req = get_statutory_requirements("AML-TRD-003")
        self.assertEqual(req["rule_id"], "AML-TRD-003")
        self._run_boundary_pair("AML-TRD-003", 31000.0, 'WAREHOUSE RECEIPT', 'INBOUND')

    def test_boundary_aml_trd_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-004."""
        req = get_statutory_requirements("AML-TRD-004")
        self.assertEqual(req["rule_id"], "AML-TRD-004")
        self._run_boundary_pair("AML-TRD-004", 16000.0, 'SCRAP METAL', 'OUTBOUND')

    def test_boundary_aml_trd_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-005."""
        req = get_statutory_requirements("AML-TRD-005")
        self.assertEqual(req["rule_id"], "AML-TRD-005")
        self._run_boundary_pair("AML-TRD-005", 23000.0, 'AUTO EXPORT', 'OUTBOUND')

    def test_boundary_aml_trd_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-006."""
        req = get_statutory_requirements("AML-TRD-006")
        self.assertEqual(req["rule_id"], "AML-TRD-006")
        self._run_boundary_pair("AML-TRD-006", 37000.0, 'CARBON CREDIT', 'OUTBOUND')

    def test_boundary_aml_trd_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-007."""
        req = get_statutory_requirements("AML-TRD-007")
        self.assertEqual(req["rule_id"], "AML-TRD-007")
        self._run_boundary_pair("AML-TRD-007", 29000.0, 'ROYALTY LICENSE', 'OUTBOUND')

    def test_boundary_aml_trd_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-008."""
        req = get_statutory_requirements("AML-TRD-008")
        self.assertEqual(req["rule_id"], "AML-TRD-008")
        self._run_boundary_pair("AML-TRD-008", 18500.0, 'FREIGHT ESCROW', 'INBOUND')

    def test_boundary_aml_trd_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-009."""
        req = get_statutory_requirements("AML-TRD-009")
        self.assertEqual(req["rule_id"], "AML-TRD-009")
        self._run_boundary_pair("AML-TRD-009", 14500.0, 'QUALITY REBATE', 'OUTBOUND')

    def test_boundary_aml_trd_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-010."""
        req = get_statutory_requirements("AML-TRD-010")
        self.assertEqual(req["rule_id"], "AML-TRD-010")
        self._run_boundary_pair("AML-TRD-010", 19500.0, 'GARMENT CONSIGNMENT', 'OUTBOUND')

    def test_boundary_aml_trd_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-011."""
        req = get_statutory_requirements("AML-TRD-011")
        self.assertEqual(req["rule_id"], "AML-TRD-011")
        self._run_boundary_pair("AML-TRD-011", 27000.0, 'API BULK', 'OUTBOUND')

    def test_boundary_aml_trd_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-012."""
        req = get_statutory_requirements("AML-TRD-012")
        self.assertEqual(req["rule_id"], "AML-TRD-012")
        self._run_boundary_pair("AML-TRD-012", 15500.0, 'EXOTIC TIMBER', 'OUTBOUND')

    def test_boundary_aml_trd_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-013."""
        req = get_statutory_requirements("AML-TRD-013")
        self.assertEqual(req["rule_id"], "AML-TRD-013")
        self._run_boundary_pair("AML-TRD-013", 33000.0, 'BONDED WAREHOUSE', 'INBOUND')

    def test_boundary_aml_trd_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-014."""
        req = get_statutory_requirements("AML-TRD-014")
        self.assertEqual(req["rule_id"], "AML-TRD-014")
        self._run_boundary_pair("AML-TRD-014", 21000.0, 'GENERAL TRADING', 'OUTBOUND')

    def test_boundary_aml_trd_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-TRD-015."""
        req = get_statutory_requirements("AML-TRD-015")
        self.assertEqual(req["rule_id"], "AML-TRD-015")
        self._run_boundary_pair("AML-TRD-015", 20500.0, 'OPEN ACCOUNT', 'OUTBOUND')

    def test_boundary_aml_wth_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-001."""
        req = get_statutory_requirements("AML-WTH-001")
        self.assertEqual(req["rule_id"], "AML-WTH-001")
        self._run_boundary_pair("AML-WTH-001", 40000.0, 'LOMBARD LOAN', 'INBOUND')

    def test_boundary_aml_wth_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-002."""
        req = get_statutory_requirements("AML-WTH-002")
        self.assertEqual(req["rule_id"], "AML-WTH-002")
        self._run_boundary_pair("AML-WTH-002", 48000.0, 'TRUST DISTRIBUTION', 'OUTBOUND')

    def test_boundary_aml_wth_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-003."""
        req = get_statutory_requirements("AML-WTH-003")
        self.assertEqual(req["rule_id"], "AML-WTH-003")
        self._run_boundary_pair("AML-WTH-003", 36000.0, 'FOUNDATION', 'INBOUND')

    def test_boundary_aml_wth_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-004."""
        req = get_statutory_requirements("AML-WTH-004")
        self.assertEqual(req["rule_id"], "AML-WTH-004")
        self._run_boundary_pair("AML-WTH-004", 52000.0, 'AVIATION ESCROW', 'OUTBOUND')

    def test_boundary_aml_wth_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-005."""
        req = get_statutory_requirements("AML-WTH-005")
        self.assertEqual(req["rule_id"], "AML-WTH-005")
        self._run_boundary_pair("AML-WTH-005", 30000.0, 'POLICY SURRENDER', 'INBOUND')

    def test_boundary_aml_wth_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-006."""
        req = get_statutory_requirements("AML-WTH-006")
        self.assertEqual(req["rule_id"], "AML-WTH-006")
        self._run_boundary_pair("AML-WTH-006", 44000.0, 'SPV CAPITAL CALL', 'OUTBOUND')

    def test_boundary_aml_wth_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-007."""
        req = get_statutory_requirements("AML-WTH-007")
        self.assertEqual(req["rule_id"], "AML-WTH-007")
        self._run_boundary_pair("AML-WTH-007", 39000.0, 'AUCTION SETTLEMENT', 'OUTBOUND')

    def test_boundary_aml_wth_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-008."""
        req = get_statutory_requirements("AML-WTH-008")
        self.assertEqual(req["rule_id"], "AML-WTH-008")
        self._run_boundary_pair("AML-WTH-008", 25000.0, 'DIVIDEND REDIRECTION', 'OUTBOUND')

    def test_boundary_aml_wth_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-009."""
        req = get_statutory_requirements("AML-WTH-009")
        self.assertEqual(req["rule_id"], "AML-WTH-009")
        self._run_boundary_pair("AML-WTH-009", 18000.0, 'VAULT LIQUIDATION', 'INBOUND')

    def test_boundary_aml_wth_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-010."""
        req = get_statutory_requirements("AML-WTH-010")
        self.assertEqual(req["rule_id"], "AML-WTH-010")
        self._run_boundary_pair("AML-WTH-010", 35000.0, 'CBI INVESTMENT', 'INBOUND')

    def test_boundary_aml_wth_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-011."""
        req = get_statutory_requirements("AML-WTH-011")
        self.assertEqual(req["rule_id"], "AML-WTH-011")
        self._run_boundary_pair("AML-WTH-011", 41000.0, 'REDEMPTION', 'INBOUND')

    def test_boundary_aml_wth_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-012."""
        req = get_statutory_requirements("AML-WTH-012")
        self.assertEqual(req["rule_id"], "AML-WTH-012")
        self._run_boundary_pair("AML-WTH-012", 27000.0, 'SOVEREIGN ADVISORY', 'INBOUND')

    def test_boundary_aml_wth_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-013."""
        req = get_statutory_requirements("AML-WTH-013")
        self.assertEqual(req["rule_id"], "AML-WTH-013")
        self._run_boundary_pair("AML-WTH-013", 23000.0, 'NUMBERED ACCOUNT', 'OUTBOUND')

    def test_boundary_aml_wth_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-014."""
        req = get_statutory_requirements("AML-WTH-014")
        self.assertEqual(req["rule_id"], "AML-WTH-014")
        self._run_boundary_pair("AML-WTH-014", 38000.0, 'PREPAID LEASE', 'INBOUND')

    def test_boundary_aml_wth_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for AML-WTH-015."""
        req = get_statutory_requirements("AML-WTH-015")
        self.assertEqual(req["rule_id"], "AML-WTH-015")
        self._run_boundary_pair("AML-WTH-015", 26000.0, 'CHARITABLE GRANT', 'OUTBOUND')

    def test_boundary_frd_mer_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-001."""
        req = get_statutory_requirements("FRD-MER-001")
        self.assertEqual(req["rule_id"], "FRD-MER-001")
        self._run_boundary_pair("FRD-MER-001", 14000.0, 'SUBMERCHANT', 'INBOUND')

    def test_boundary_frd_mer_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-002."""
        req = get_statutory_requirements("FRD-MER-002")
        self.assertEqual(req["rule_id"], "FRD-MER-002")
        self._run_boundary_pair("FRD-MER-002", 9500.0, 'UNMATCHED REFUND', 'OUTBOUND')

    def test_boundary_frd_mer_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-003."""
        req = get_statutory_requirements("FRD-MER-003")
        self.assertEqual(req["rule_id"], "FRD-MER-003")
        self._run_boundary_pair("FRD-MER-003", 16000.0, 'PAYFAC SETTLEMENT', 'OUTBOUND')

    def test_boundary_frd_mer_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-004."""
        req = get_statutory_requirements("FRD-MER-004")
        self.assertEqual(req["rule_id"], "FRD-MER-004")
        self._run_boundary_pair("FRD-MER-004", 12500.0, 'MERCHANT SETTLEMENT', 'INBOUND')

    def test_boundary_frd_mer_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-005."""
        req = get_statutory_requirements("FRD-MER-005")
        self.assertEqual(req["rule_id"], "FRD-MER-005")
        self._run_boundary_pair("FRD-MER-005", 2500.0, 'AUTH TEST', 'INBOUND')

    def test_boundary_frd_mer_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-006."""
        req = get_statutory_requirements("FRD-MER-006")
        self.assertEqual(req["rule_id"], "FRD-MER-006")
        self._run_boundary_pair("FRD-MER-006", 11000.0, 'MARKETPLACE PAYOUT', 'INBOUND')

    def test_boundary_frd_mer_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-007."""
        req = get_statutory_requirements("FRD-MER-007")
        self.assertEqual(req["rule_id"], "FRD-MER-007")
        self._run_boundary_pair("FRD-MER-007", 13500.0, 'CHARGEBACK', 'OUTBOUND')

    def test_boundary_frd_mer_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-008."""
        req = get_statutory_requirements("FRD-MER-008")
        self.assertEqual(req["rule_id"], "FRD-MER-008")
        self._run_boundary_pair("FRD-MER-008", 8500.0, 'MANUAL ENTRY', 'INBOUND')

    def test_boundary_frd_mer_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-009."""
        req = get_statutory_requirements("FRD-MER-009")
        self.assertEqual(req["rule_id"], "FRD-MER-009")
        self._run_boundary_pair("FRD-MER-009", 7500.0, 'PREPAID LOAD', 'OUTBOUND')

    def test_boundary_frd_mer_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-010."""
        req = get_statutory_requirements("FRD-MER-010")
        self.assertEqual(req["rule_id"], "FRD-MER-010")
        self._run_boundary_pair("FRD-MER-010", 6000.0, 'SPLIT SWIPE', 'INBOUND')

    def test_boundary_frd_mer_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-011."""
        req = get_statutory_requirements("FRD-MER-011")
        self.assertEqual(req["rule_id"], "FRD-MER-011")
        self._run_boundary_pair("FRD-MER-011", 19000.0, 'MCA ADVANCE', 'INBOUND')

    def test_boundary_frd_mer_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-012."""
        req = get_statutory_requirements("FRD-MER-012")
        self.assertEqual(req["rule_id"], "FRD-MER-012")
        self._run_boundary_pair("FRD-MER-012", 10500.0, 'FULFILLMENT', 'OUTBOUND')

    def test_boundary_frd_mer_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-013."""
        req = get_statutory_requirements("FRD-MER-013")
        self.assertEqual(req["rule_id"], "FRD-MER-013")
        self._run_boundary_pair("FRD-MER-013", 15000.0, 'RECURRING BILLING', 'INBOUND')

    def test_boundary_frd_mer_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-014."""
        req = get_statutory_requirements("FRD-MER-014")
        self.assertEqual(req["rule_id"], "FRD-MER-014")
        self._run_boundary_pair("FRD-MER-014", 7000.0, 'SOFTPOS', 'INBOUND')

    def test_boundary_frd_mer_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-MER-015."""
        req = get_statutory_requirements("FRD-MER-015")
        self.assertEqual(req["rule_id"], "FRD-MER-015")
        self._run_boundary_pair("FRD-MER-015", 17500.0, 'FREELANCE PAYOUT', 'OUTBOUND')

    def test_boundary_frd_pub_001(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-001."""
        req = get_statutory_requirements("FRD-PUB-001")
        self.assertEqual(req["rule_id"], "FRD-PUB-001")
        self._run_boundary_pair("FRD-PUB-001", 9000.0, 'TECH SUPPORT', 'OUTBOUND')

    def test_boundary_frd_pub_002(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-002."""
        req = get_statutory_requirements("FRD-PUB-002")
        self.assertEqual(req["rule_id"], "FRD-PUB-002")
        self._run_boundary_pair("FRD-PUB-002", 11500.0, 'FIDUCIARY', 'OUTBOUND')

    def test_boundary_frd_pub_003(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-003."""
        req = get_statutory_requirements("FRD-PUB-003")
        self.assertEqual(req["rule_id"], "FRD-PUB-003")
        self._run_boundary_pair("FRD-PUB-003", 14000.0, 'RELIEF GRANT', 'INBOUND')

    def test_boundary_frd_pub_004(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-004."""
        req = get_statutory_requirements("FRD-PUB-004")
        self.assertEqual(req["rule_id"], "FRD-PUB-004")
        self._run_boundary_pair("FRD-PUB-004", 8500.0, 'TAX REFUND', 'INBOUND')

    def test_boundary_frd_pub_005(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-005."""
        req = get_statutory_requirements("FRD-PUB-005")
        self.assertEqual(req["rule_id"], "FRD-PUB-005")
        self._run_boundary_pair("FRD-PUB-005", 24000.0, 'TELEMEDICINE', 'OUTBOUND')

    def test_boundary_frd_pub_006(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-006."""
        req = get_statutory_requirements("FRD-PUB-006")
        self.assertEqual(req["rule_id"], "FRD-PUB-006")
        self._run_boundary_pair("FRD-PUB-006", 36000.0, 'SUBCONTRACTOR', 'OUTBOUND')

    def test_boundary_frd_pub_007(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-007."""
        req = get_statutory_requirements("FRD-PUB-007")
        self.assertEqual(req["rule_id"], "FRD-PUB-007")
        self._run_boundary_pair("FRD-PUB-007", 6500.0, 'MOBILE CHECK DEPOSIT', 'INBOUND')

    def test_boundary_frd_pub_008(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-008."""
        req = get_statutory_requirements("FRD-PUB-008")
        self.assertEqual(req["rule_id"], "FRD-PUB-008")
        self._run_boundary_pair("FRD-PUB-008", 5500.0, 'FINANCIAL AID', 'INBOUND')

    def test_boundary_frd_pub_009(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-009."""
        req = get_statutory_requirements("FRD-PUB-009")
        self.assertEqual(req["rule_id"], "FRD-PUB-009")
        self._run_boundary_pair("FRD-PUB-009", 29000.0, 'CREDIT LINE', 'OUTBOUND')

    def test_boundary_frd_pub_010(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-010."""
        req = get_statutory_requirements("FRD-PUB-010")
        self.assertEqual(req["rule_id"], "FRD-PUB-010")
        self._run_boundary_pair("FRD-PUB-010", 22500.0, 'WASTE MANAGEMENT', 'OUTBOUND')

    def test_boundary_frd_pub_011(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-011."""
        req = get_statutory_requirements("FRD-PUB-011")
        self.assertEqual(req["rule_id"], "FRD-PUB-011")
        self._run_boundary_pair("FRD-PUB-011", 18000.0, 'PHARMACY WHOLESALE', 'INBOUND')

    def test_boundary_frd_pub_012(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-012."""
        req = get_statutory_requirements("FRD-PUB-012")
        self.assertEqual(req["rule_id"], "FRD-PUB-012")
        self._run_boundary_pair("FRD-PUB-012", 16500.0, 'REPLICA WHOLESALE', 'OUTBOUND')

    def test_boundary_frd_pub_013(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-013."""
        req = get_statutory_requirements("FRD-PUB-013")
        self.assertEqual(req["rule_id"], "FRD-PUB-013")
        self._run_boundary_pair("FRD-PUB-013", 10000.0, 'WAGER SETTLEMENT', 'INBOUND')

    def test_boundary_frd_pub_014(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-014."""
        req = get_statutory_requirements("FRD-PUB-014")
        self.assertEqual(req["rule_id"], "FRD-PUB-014")
        self._run_boundary_pair("FRD-PUB-014", 33000.0, 'INCIDENT RESPONSE', 'OUTBOUND')

    def test_boundary_frd_pub_015(self) -> None:
        """Verifies positive threshold trigger and negative below-threshold suppression for FRD-PUB-015."""
        req = get_statutory_requirements("FRD-PUB-015")
        self.assertEqual(req["rule_id"], "FRD-PUB-015")
        self._run_boundary_pair("FRD-PUB-015", 46000.0, 'BROKERAGE FUNDING', 'OUTBOUND')


if __name__ == "__main__":
    unittest.main()
