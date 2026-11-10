"""
Comprehensive unit and matrix boundary tests for the 175-Rule Global & Sector Typology Suite
and the UNODC goAML 5.0 XML Regulatory Exporter.
"""
import unittest

from backend.app.cases.service import CaseManagementService
from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.reporting.goaml_xml import GoAmlXmlExporter
from backend.app.typologies.engine import TypologyEngine
from backend.app.typologies.global_registry import (
    get_175_detector_map,
    get_full_175_catalog,
)


class Full175TypologyMatrixAndGoAmlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.engine = TypologyEngine(cls.db)
        cls.goaml = GoAmlXmlExporter(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_175_detectors_registered_and_executable(self) -> None:
        detectors = get_175_detector_map()
        catalog = get_full_175_catalog()
        self.assertEqual(len(detectors), 175)
        self.assertEqual(len(catalog), 175)

        ctx = self.engine.build_context()
        for rule_id, detector in detectors.items():
            res = detector.evaluate(ctx)
            self.assertIsInstance(res, list, f"Detector {rule_id} did not return a list")

    def test_unodc_goaml_5_xml_export(self) -> None:
        cases = CaseManagementService(self.db).list_cases()
        self.assertGreaterEqual(len(cases), 1)
        out = self.goaml.export_goaml_str_xml(cases[0]["id"])
        self.assertTrue(out["is_valid"])
        self.assertEqual(out["standard"], "UNODC_GOAML_5.0")
        self.assertIn("<report_code>STR</report_code>", out["xml_content"])


if __name__ == "__main__":
    unittest.main()
