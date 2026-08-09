# SentinelGraph — Testing & Verification Guide (`TESTING.md`)

---

## 1. Testing Pyramid & Architecture

SentinelGraph maintains a comprehensive automated test suite built on Python's standard `unittest` framework and `fastapi.testclient.TestClient` (via `httpx`), requiring zero external services or network access.

| Test Layer | Directory | Scope & Coverage |
| :--- | :--- | :--- |
| **Unit Tests** | `tests/unit/` | Tests individual components in isolation: 6-factor KYC risk scoring, Jaro-Winkler/Levenshtein/Soundex fuzzy matching, all 25 AML/fraud typology detectors at exact threshold boundaries, graph cycle/SCC/PageRank algorithms, and cryptographic HMAC audit chaining. |
| **Integration Tests** | `tests/integration/` | Tests database migrations, repository persistence, RuleForge shadow-mode backtesting accuracy against labeled datasets, and multi-alert correlation into cases. |
| **End-to-End (E2E) Workflow Tests** | `tests/e2e/` | Simulates full multi-persona compliance workflows via the REST API: L1 login & alert triage -> L2 graph investigation & SAR narrative generation -> Four-Eyes QA enforcement (verifying self-approval rejection) -> QA approval & FinCEN SAR filing -> Audit ledger integrity verification. |

---

## 2. Running Tests on Windows (PowerShell / VS Code) & Linux

### Run the Entire Test Suite
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### Run Specific Test Suites
```powershell
# Unit tests only
python -m unittest discover -s tests/unit -p "test_*.py" -v

# Integration tests only
python -m unittest discover -s tests/integration -p "test_*.py" -v

# End-to-End API & workflow tests
python -m unittest discover -s tests/e2e -p "test_*.py" -v
```

---

## 3. Boundary & Adversarial Test Scenarios Verified
1. **Cash Structuring Boundaries:** Verifies that single $10,000.01 deposits trigger CTR reporting rather than sub-CTR evasion (`AML-STR-001`), whereas three $3,400 cash deposits within 48 hours trigger both rolling aggregation (`AML-STR-002`) and structuring alerts.
2. **Pass-Through Velocity Ratios:** Verifies that an account receiving $50,000 and wiring out $46,500 (93% outflow ratio) within 18 hours triggers `AML-LAY-001`, whereas normal commercial payroll dispersion over 14 days does not.
3. **Graph Cycle & Mule Ring Detection:** Verifies that a 4-hop temporal cycle ($A \to B \to C \to D \to A$) is detected by the temporal cycle finder and Tarjan SCC algorithm.
4. **Four-Eyes Separation of Duties:** Verifies that if Investigator `usr-002` escalates and submits a case for QA, an attempt by `usr-002` to approve the SAR returns HTTP `403 Forbidden` (`SeparationOfDutiesError`).
5. **Audit Tamper Detection:** Verifies that mutating a single character in an existing `audit_logs` record causes `AuditService.verify_chain_integrity()` to immediately detect the exact corrupted sequence ID.
