"""
End-to-End (E2E) FastAPI tests exercising the full compliance lifecycle:
1. Operator authentication & RBAC enforcement
2. Alert queue retrieval & L1/L2 escalation into an investigation Case
3. FinCEN 5-W SAR narrative generation & SHA-256 verification
4. Four-Eyes Separation of Duties enforcement (verifying an investigator cannot QA-approve their own case)
5. Independent QA Officer approval, FinCEN SAR filing, and Cryptographic Audit Chain verification
"""
import unittest
from fastapi.testclient import TestClient

from backend.app.api.routes import get_db
from backend.app.db.connection import DatabaseManager
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.main import create_app


class EndToEndComplianceWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.test_db = DatabaseManager(":memory:")
        SyntheticCrimeSeeder(cls.test_db).seed_all()

        app = create_app()
        app.dependency_overrides[get_db] = lambda: cls.test_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.test_db.close()

    def _login(self, username: str, password: str) -> str:
        res = self.client.post("/api/v1/auth/login", json={"username": username, "password": password})
        self.assertEqual(res.status_code, 200, res.text)
        return res.json()["access_token"]

    def test_full_l1_l2_qa_sar_and_four_eyes_separation_workflow(self) -> None:
        l2_token = self._login("l2_investigator", "Investigator#2026!Secure")
        qa_token = self._login("qa_officer", "Compliance#2026!Secure")
        l2_headers = {"Authorization": f"Bearer {l2_token}"}
        qa_headers = {"Authorization": f"Bearer {qa_token}"}

        # 1. Verify Dashboard KPIs
        dash_res = self.client.get("/api/v1/analytics/dashboard", headers=l2_headers)
        self.assertEqual(dash_res.status_code, 200)
        self.assertTrue(dash_res.json()["audit_ledger_integrity"]["is_valid"])

        # 2. Fetch NEW alerts and escalate one to a Case as L2 Investigator
        alerts_res = self.client.get("/api/v1/alerts?status=NEW", headers=l2_headers)
        self.assertEqual(alerts_res.status_code, 200)
        new_alerts = alerts_res.json()["alerts"]
        self.assertGreater(len(new_alerts), 0)
        target_alert_id = new_alerts[0]["id"]

        triage_res = self.client.post(
            f"/api/v1/alerts/{target_alert_id}/triage",
            headers=l2_headers,
            json={
                "action": "ESCALATE_TO_CASE",
                "case_title": "E2E Multi-Hop Layering & Structuring Investigation",
                "case_priority": "CRITICAL",
            },
        )
        self.assertEqual(triage_res.status_code, 200)
        case_id = triage_res.json()["case_id"]
        self.assertIsNotNone(case_id)

        # 3. Generate FinCEN 5-W SAR Narrative and auto-submit for QA
        sar_res = self.client.post(
            f"/api/v1/cases/{case_id}/generate-sar",
            headers=l2_headers,
            json={
                "filing_type": "INITIAL",
                "custom_why_how_addendum": "E2E forensic verification of funds flow.",
                "auto_submit_for_qa": True,
            },
        )
        self.assertEqual(sar_res.status_code, 200, sar_res.text)
        sar_data = sar_res.json()
        self.assertIn("SUBJECT IDENTIFICATION (WHO):", sar_data["full_narrative_text"])
        self.assertIn("INSTRUMENTS & FINANCIAL MECHANISMS (WHAT):", sar_data["full_narrative_text"])
        self.assertEqual(len(sar_data["content_sha256"]), 64)

        # 4. Verify Four-Eyes Separation of Duties: L2 Investigator attempting to QA-approve their own case MUST fail with 403
        self_approve_res = self.client.post(
            f"/api/v1/cases/{case_id}/transition",
            headers=l2_headers,
            json={
                "target_status": "SAR_APPROVED",
                "notes": "Attempting self-approval bypass",
            },
        )
        self.assertEqual(self_approve_res.status_code, 403)
        self.assertEqual(self_approve_res.json()["error"]["code"], "SEPARATION_OF_DUTIES_VIOLATION")

        # 5. Independent QA Compliance Officer approves and files the SAR
        qa_approve_res = self.client.post(
            f"/api/v1/cases/{case_id}/transition",
            headers=qa_headers,
            json={
                "target_status": "SAR_APPROVED",
                "notes": "Independent Four-Eyes QA review passed.",
            },
        )
        self.assertEqual(qa_approve_res.status_code, 200, qa_approve_res.text)
        self.assertEqual(qa_approve_res.json()["status"], "SAR_APPROVED")

        qa_file_res = self.client.post(
            f"/api/v1/cases/{case_id}/transition",
            headers=qa_headers,
            json={
                "target_status": "SAR_FILED",
                "notes": "Submitted to FinCEN BSA E-Filing system.",
            },
        )
        self.assertEqual(qa_file_res.status_code, 200)
        self.assertEqual(qa_file_res.json()["status"], "SAR_FILED")
        self.assertIsNotNone(qa_file_res.json()["sar_reports"][0]["fincen_bsa_id"])

        # 6. Verify Cryptographic Audit Ledger Integrity after all mutations
        audit_res = self.client.get("/api/v1/audit/verify", headers=qa_headers)
        self.assertEqual(audit_res.status_code, 200)
        self.assertTrue(audit_res.json()["is_valid"])


if __name__ == "__main__":
    unittest.main()
