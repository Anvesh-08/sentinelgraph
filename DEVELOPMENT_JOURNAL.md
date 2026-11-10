# SentinelGraph — Engineering Development Journal (`DEVELOPMENT_JOURNAL.md`)

This engineering journal records the chronological design decisions, debugging fixes, architectural trade-offs, and verification milestones across Phases 1 through 7.

---

## Entry 1 — Phase 1: Product Discovery & Domain Selection
- **Decision:** Selected **SentinelGraph** (combining an AML/Fraud Case Investigation Workbench with the **RuleForge** Shadow-Mode Rule Backtesting Engine).
- **Rationale:** Standard open-source fraud projects stop at toy anomaly scripts and ignore post-alert investigation, multi-hop graph link analysis, Four-Eyes QA compliance, and FinCEN 5-W SAR narrative generation.
- **Outcome:** Authored [`PRODUCT_SPEC.md`](PRODUCT_SPEC.md) defining 4 operator personas and 25 concrete AML/Fraud typology rules across 5 families.

## Entry 2 — Phase 2: Architecture & Database Modeling
- **Decision:** Adopted a layered modular monolith backed by SQLite in `WAL` mode (with `PRAGMA foreign_keys = ON`) and an in-memory property graph projection.
- **Trade-offs:** Avoids requiring external Neo4j or Docker containers on Windows/PowerShell while providing sub-50ms K-hop ego-network traversal and Tarjan SCC ring detection.
- **Outcome:** Authored [`ARCHITECTURE.md`](ARCHITECTURE.md), [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md), [`API_DOCUMENTATION.md`](API_DOCUMENTATION.md), and [`SECURITY.md`](SECURITY.md).

## Entry 3 — Phase 3: Security, Persistence & Hash-Chained Audit Ledger
- **Implementation:** Built `PBKDF2-HMAC-SHA256` (210,000 iterations) password hashing, stateless HMAC-SHA256 bearer tokens, 5-role RBAC enforcement, checksum-verified SQL migrations, and `AuditService` chaining every record with `HMAC-SHA256(previous_hash | timestamp | actor | action | entity | payload)`.

## Entry 4 — Phase 4: 25-Rule Typology Engine, Graph Forensics, RuleForge & SAR Builder
- **Implementation:**
  - Implemented all 25 AML & Fraud typology detectors (`AML-STR-001`..`005`, `AML-LAY-001`..`005`, `AML-NET-001`..`005`, `AML-GEO-001`..`005`, `FRD-BEH-001`..`005`) plus automatic FinCEN CTR aggregation (> $10,000/day cash).
  - Implemented K-hop ego network extraction, temporal pathfinding, Tarjan's Strongly Connected Components, and iterative PageRank centrality.
  - Built `RuleSimulationEngine` for side-by-side baseline vs. candidate parameter backtesting.
  - Built `CaseManagementService` enforcing Four-Eyes Separation of Duties and `FinCENSarGenerator` producing 5-W narratives.
- **Debugging & Root-Cause Fixes During Integration:**
  1. *Bug 1 (`7dea0ec`):* When generating a SAR narrative for an escalated case, `CaseManagementService.get_case()` queried `SELECT * FROM alerts WHERE case_id = ?` without joining `typology_rules`, causing a `KeyError: 'rule_name'` in `FinCENSarGenerator`. Fixed by joining `typology_rules r ON r.id = a.rule_id` in `get_case()`.
  2. *Bug 2 (`b21b7fa`):* In `RuleSimulationEngine._determine_ground_truth_positive_accounts()`, the SQL query selected `a.account_id` from `accounts a` instead of `a.id AS account_id`. Fixed and verified with `init-db --seed`.

## Entry 5 — Phase 5, 6 & 7: Frontend Workbench, Automated Test Suite & Eligibility Audit
- **Implementation:** Built the interactive Investigator Workbench (`frontend/public/index.html`) and TypeScript SDK (`frontend/src/`), plus comprehensive unit, integration, and E2E test suites (`tests/`) and Windows PowerShell automation scripts (`scripts/`).
