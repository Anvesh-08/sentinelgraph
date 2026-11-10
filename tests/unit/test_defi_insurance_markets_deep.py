"""
Unit tests for the 45 DeFi, Insurance, and Capital Markets typology detectors.
"""
import unittest
from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.typologies.engine import TypologyEngine
from backend.app.typologies.global_registry import get_220_detector_map, get_full_220_catalog


class AdvancedSector220DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.engine = TypologyEngine(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_220_detectors_integrity(self) -> None:
        detectors = get_220_detector_map()
        catalog = get_full_220_catalog()
        self.assertEqual(len(detectors), 220)
        self.assertEqual(len(catalog), 220)

        ctx = self.engine.build_context()
        for rid in ("AML-GOV-001", "FRD-INS-001", "FRD-MKT-001"):
            self.assertIn(rid, detectors)
            res = detectors[rid].evaluate(ctx)
            self.assertIsInstance(res, list)


if __name__ == "__main__":
    unittest.main()
