"""
Unit tests for PBKDF2-HMAC-SHA256 password hashing, stateless HMAC-SHA256 bearer tokens,
RBAC permissions, tamper-evident audit hash chaining, and fuzzy sanctions algorithms.
"""
import unittest

from backend.app.audit.service import AuditService
from backend.app.core.exceptions import AuditIntegrityError, AuthenticationError, AuthorizationError
from backend.app.core.security import (
    Permission,
    Role,
    assert_permission,
    create_access_token,
    decode_and_verify_token,
    hash_password,
    verify_password,
)
from backend.app.db.connection import DatabaseManager
from backend.app.db.migrator import MigrationRunner
from backend.app.sanctions.screener import (
    SanctionsScreeningService,
    jaro_winkler_similarity,
    levenshtein_similarity,
    soundex,
    token_set_similarity,
)


class SecurityAndAuditUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = DatabaseManager(":memory:")
        MigrationRunner(self.db).run_migrations()
        self.audit = AuditService(self.db)

    def tearDown(self) -> None:
        self.db.close()

    def test_pbkdf2_password_hash_and_verification(self) -> None:
        creds = hash_password("Compliance#2026!Strong")
        self.assertEqual(len(creds["password_salt"]), 32)
        self.assertTrue(verify_password("Compliance#2026!Strong", creds["password_hash"], creds["password_salt"]))
        self.assertFalse(verify_password("WrongPassword123!", creds["password_hash"], creds["password_salt"]))

    def test_stateless_hmac_token_issuance_and_expiry(self) -> None:
        token = create_access_token("usr-001", "priya_l2", Role.L2_INVESTIGATOR, "Priya Nair", ttl_seconds=3600)
        claims = decode_and_verify_token(token)
        self.assertEqual(claims["sub"], "usr-001")
        self.assertEqual(claims["role"], Role.L2_INVESTIGATOR)

        # Tamper with token payload
        parts = token.split(".")
        tampered = f"{parts[0]}.{parts[1]}a.{parts[2]}"
        with self.assertRaises(AuthenticationError):
            decode_and_verify_token(tampered)

        # Expired token
        expired_token = create_access_token("usr-001", "priya_l2", Role.L2_INVESTIGATOR, ttl_seconds=-10)
        with self.assertRaises(AuthenticationError):
            decode_and_verify_token(expired_token)

    def test_rbac_permission_enforcement(self) -> None:
        assert_permission(Role.QA_COMPLIANCE_OFFICER, Permission.APPROVE_QA_AND_FILE_SAR)
        with self.assertRaises(AuthorizationError):
            assert_permission(Role.L1_ANALYST, Permission.APPROVE_QA_AND_FILE_SAR)
        with self.assertRaises(AuthorizationError):
            assert_permission(Role.L2_INVESTIGATOR, Permission.TUNE_RULES_AND_SIMULATE)

    def test_cryptographic_audit_chain_and_tamper_detection(self) -> None:
        e1 = self.audit.record_event("usr-1", Role.L1_ANALYST, "ALERT_TRIAGED", "Alert", "alt-1", {"note": "ok"})
        e2 = self.audit.record_event("usr-2", Role.L2_INVESTIGATOR, "CASE_ESCALATED", "Case", "case-1", {"p": "HIGH"})
        self.assertEqual(e2["previous_hash"], e1["entry_hash"])

        verification = self.audit.verify_chain_integrity(raise_on_error=True)
        self.assertTrue(verification["is_valid"])
        self.assertEqual(verification["total_records_verified"], 2)

        # Simulate malicious database tampering on sequence_id = 1
        with self.db.connection() as conn:
            conn.execute("UPDATE audit_logs SET details_json = '{\"note\":\"tampered\"}' WHERE sequence_id = 1")

        broken_check = self.audit.verify_chain_integrity(raise_on_error=False)
        self.assertFalse(broken_check["is_valid"])
        self.assertGreaterEqual(len(broken_check["corrupted_entries"]), 1)
        with self.assertRaises(AuditIntegrityError):
            self.audit.verify_chain_integrity(raise_on_error=True)

    def test_fuzzy_sanctions_string_and_phonetic_matching(self) -> None:
        self.assertEqual(soundex("KHALID"), soundex("KHALED"))
        self.assertGreater(jaro_winkler_similarity("VIKTOR MOROZOV", "VICTOR MOROZOV"), 0.90)
        self.assertGreater(token_set_similarity("MOROZOV, VIKTOR ALEKSANDROVICH", "Viktor Morozov"), 0.82)
        self.assertGreater(levenshtein_similarity("TARIQ AL MANSOUR", "TARIK AL MANSUR"), 0.80)

        score, breakdown = SanctionsScreeningService.compute_composite_match(
            query_name="Tarik Al-Mansur",
            candidate_name="TARIQ AL-MANSOUR",
            query_dob="1975-02-18",
            candidate_dob="1975-02-18",
            query_country="SY",
            candidate_country="SY",
        )
        self.assertGreaterEqual(score, 0.88)
        self.assertTrue(breakdown["dob_match"])
        self.assertTrue(breakdown["country_match"])


if __name__ == "__main__":
    unittest.main()
