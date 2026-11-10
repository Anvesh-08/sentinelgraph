"""
Unit tests verifying the 100-Rule Global Typology Registry across all 10 domain families.
"""
import unittest

from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.typologies.engine import TypologyEngine
from backend.app.typologies.global_registry import get_100_detector_map, get_full_100_catalog


class Global100TypologyPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.engine = TypologyEngine(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_100_detectors_and_catalog_integrity(self) -> None:
        detectors = get_100_detector_map()
        catalog = get_full_100_catalog()
        self.assertEqual(len(detectors), 100)
        self.assertEqual(len(catalog), 100)

        ctx = self.engine.build_context()
        total_triggers = 0
        for rule_id, detector in detectors.items():
            res = detector.evaluate(ctx)
            total_triggers += len(res)
        self.assertGreaterEqual(total_triggers, 30)


if __name__ == "__main__":
    unittest.main()
