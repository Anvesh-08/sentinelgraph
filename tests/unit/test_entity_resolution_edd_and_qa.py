"""
Unit and integration tests for Probabilistic Fellegi-Sunter Entity Resolution,
OFAC 50% Ownership Control Rule, Enhanced Due Diligence (EDD) Dossiers,
and QA Risk-Stratified Sampling & Red-Team Evasion Suites.
"""
import unittest

from backend.app.db.connection import DatabaseManager
from backend.app.entity_resolution.edd_workflow import EnhancedDueDiligenceEngine
from backend.app.entity_resolution.resolver import ProbabilisticEntityResolver
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.qa_analytics.engine import QaAndRedTeamAnalyticsEngine


class EntityResolutionEddAndQaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.resolver = ProbabilisticEntityResolver(cls.db)
        cls.edd_engine = EnhancedDueDiligenceEngine(cls.db)
        cls.qa_engine = QaAndRedTeamAnalyticsEngine(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_fellegi_sunter_entity_resolution_and_ofac_50_rule(self) -> None:
        res = self.resolver.resolve_all_entities()
        self.assertEqual(res["total_customers_scanned"], 15)
        self.assertGreaterEqual(len(res["resolved_entity_links"]), 1)
        self.assertGreaterEqual(len(res["ofac_50_percent_ownership_breaches"]), 2)

    def test_enhanced_due_diligence_dossier_generation(self) -> None:
        dossier = self.edd_engine.generate_edd_dossier("cust-002")
        self.assertEqual(dossier["risk_band"], "CRITICAL")
        self.assertEqual(dossier["review_cadence_days"], 90)
        self.assertGreaterEqual(len(dossier["mandatory_edd_checklist"]), 4)

    def test_qa_sampling_and_red_team_evasion_suite(self) -> None:
        qa = self.qa_engine.generate_risk_stratified_qa_sample()
        self.assertGreaterEqual(qa["selected_qa_case_count"], 1)
        rt = self.qa_engine.run_adversarial_red_team_evasion_suite()
        self.assertEqual(rt["red_team_scenarios_executed"], 3)


if __name__ == "__main__":
    unittest.main()
