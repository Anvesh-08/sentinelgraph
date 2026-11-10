"""
Automated Integration & Scenario Calibration Tests: EU AMLD6 & UK FCA Deep Scenarios.
"""
import unittest
from backend.app.ingestion.scenario_generators_extended import ExtendedCrimeScenarioFactory
from backend.app.typologies.base import TypologyEvaluationContext
from backend.app.typologies.global_registry import get_175_detector_map


class EUAMLD6AndUKFCADeepScenariosTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detectors = get_175_detector_map()
        cls.factory = ExtendedCrimeScenarioFactory(seed=101)
        cls.customers = {
            'cust-test-1': {
                'id': 'cust-test-1',
                'customer_type': 'BUSINESS',
                'legal_name': 'Global Forensics Calibration Entity',
                'date_of_birth_or_inc': '1970-01-01',
                'residence_country': 'US',
                'nationality_or_reg_country': 'VG',
                'occupation_or_industry': 'INTERNATIONAL TRADING',
                'expected_monthly_volume_usd': 5000.0,
                'pep_flag': 1,
                'risk_band': 'CRITICAL',
                'sanctions_status': 'CLEAR',
            }
        }
        cls.accounts = {
            'acct-test-1': {
                'id': 'acct-test-1',
                'customer_id': 'cust-test-1',
                'account_number': 'SG-CALIB-0001',
                'status': 'ACTIVE',
            }
        }

    def test_amld6_third_country_evaluation(self) -> None:
        """Verifies trigger detection for AML-EUK-001 using generate_eu_amld6_high_risk_corridor_chain."""
        txs = self.factory.generate_eu_amld6_high_risk_corridor_chain('acct-test-1', 'acct-target-1', 'cust-test-1', hop_count=3)
        ctx = TypologyEvaluationContext(self.customers, self.accounts, txs)
        detector = self.detectors['AML-EUK-001']
        triggers = detector.evaluate(ctx)
        self.assertGreaterEqual(len(triggers), 1)
        self.assertEqual(triggers[0].rule_id, 'AML-EUK-001')

    def test_uk_app_scam_drain_evaluation(self) -> None:
        """Verifies trigger detection for AML-EUK-002 using generate_uk_app_scam_coercion_drain."""
        txs = self.factory.generate_uk_app_scam_coercion_drain('acct-test-1', 'acct-target-1', 'cust-test-1', hop_count=3)
        ctx = TypologyEvaluationContext(self.customers, self.accounts, txs)
        detector = self.detectors['AML-EUK-002']
        triggers = detector.evaluate(ctx)
        self.assertGreaterEqual(len(triggers), 1)
        self.assertEqual(triggers[0].rule_id, 'AML-EUK-002')


if __name__ == "__main__":
    unittest.main()
