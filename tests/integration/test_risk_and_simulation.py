"""
Integration tests for the 6-Factor Composite KYC/KYB Risk Engine, CTR aggregation,
and RuleForge Shadow-Mode Backtesting Studio.
"""
import unittest

from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.risk.engine import CompositeRiskEngine
from backend.app.simulation.engine import RuleSimulationEngine


class RiskAndSimulationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.risk_engine = CompositeRiskEngine(cls.db)
        cls.sim_engine = RuleSimulationEngine(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_composite_risk_differentiation_high_vs_low(self) -> None:
        # cust-002 (Baltic Horizon Trading Ltd: BVI/Panama, PEP UBO, Crypto/Offshore Wires) -> CRITICAL
        high_res = self.risk_engine.evaluate_customer("cust-002", persist=True)
        # cust-013 (Hannah Lindqvist: Domestic Payroll) -> LOW
        low_res = self.risk_engine.evaluate_customer("cust-013", persist=True)

        self.assertEqual(high_res["risk_band"], "CRITICAL")
        self.assertGreaterEqual(high_res["composite_risk_score"], 85.0)
        self.assertEqual(low_res["risk_band"], "LOW")
        self.assertLess(low_res["composite_risk_score"], 35.0)

    def test_ruleforge_shadow_backtest_metrics(self) -> None:
        report = self.sim_engine.run_shadow_backtest(
            rule_id="AML-LAY-001",
            candidate_parameters={
                "min_inbound_usd": 10000.0,
                "min_pass_through_ratio": 0.80,
                "max_pass_through_ratio": 1.15,
                "window_hours": 24,
            },
            actor_user_id="usr-eng",
            notes="Integration test backtest on pass-through conduit threshold",
        )
        self.assertEqual(report["rule_id"], "AML-LAY-001")
        self.assertIn("confusion_matrix", report)
        self.assertGreaterEqual(report["confusion_matrix"]["true_positives"], 1)
        self.assertGreater(report["f1_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
