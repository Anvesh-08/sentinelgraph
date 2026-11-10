"""
Unit tests for FinCEN BSA E-Filing XML 2.0 and India FIU-IND FINnet 2.0 (STR & CBWTR) XML exporters.
"""
import unittest

from backend.app.cases.service import CaseManagementService
from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.reporting.fincen_bsa_xml import FinCenBsaXmlExporter
from backend.app.reporting.fiu_ind_finnet_xml import FiuIndFinnetExporter


class RegulatoryXmlExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.db).seed_all()
        cls.fincen_exporter = FinCenBsaXmlExporter(cls.db)
        cls.fiu_exporter = FiuIndFinnetExporter(cls.db)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.db.close()

    def test_fincen_bsa_sar_xml_export_and_schema_validation(self) -> None:
        cases = CaseManagementService(self.db).list_cases()
        sar_cases = [c for c in cases if c["status"] == "SAR_FILED"]
        self.assertGreaterEqual(len(sar_cases), 1)

        res = self.fincen_exporter.export_sar_xml(sar_cases[0]["id"])
        self.assertTrue(res["validation"]["is_valid"], res["validation"])
        self.assertIn("<FormTypeCode>SARX</FormTypeCode>", res["xml_content"])
        self.assertIn("<SuspiciousActivitySubtype>", res["xml_content"])

    def test_fiu_ind_finnet2_str_and_cbwtr_export(self) -> None:
        cases = CaseManagementService(self.db).list_cases()
        str_res = self.fiu_exporter.export_fiu_ind_str_xml(cases[0]["id"])
        self.assertTrue(str_res["is_valid"])
        self.assertGreater(str_res["total_suspicious_inr"], 100000.0)
        self.assertIn("<ReportType>STR</ReportType>", str_res["xml_content"])

        cbwtr_res = self.fiu_exporter.export_cbwtr_batch_xml(min_amount_inr=500000.0)
        self.assertGreaterEqual(cbwtr_res["qualifying_wire_count"], 3)
        self.assertIn("<ReportType>CBWTR</ReportType>", cbwtr_res["xml_content"])


if __name__ == "__main__":
    unittest.main()
