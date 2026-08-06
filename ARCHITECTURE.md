# SentinelGraph — System Architecture (`ARCHITECTURE.md`)

**Version:** 1.0.0  
**Pattern:** Layered Domain-Driven Modular Monolith with Event-Driven Pipeline & Graph Forensics Core  

---

## 1. High-Level Architectural Overview

SentinelGraph is engineered with a strict separation of concerns across six distinct layers so that transaction ingestion, typology evaluation, shadow-mode simulation, graph link analysis, and regulatory case workflows operate deterministically without tight coupling.

```
+--------------------------------------------------------------------------------------------------+
|                        PRESENTATION & CLIENT LAYER (React / TypeScript / HTML5)                  |
|  [Executive KPI Dashboard]  [Alert Triage Queue]  [Multi-Hop Graph Studio]  [RuleForge Backtest] |
|  [4-Eyes Case Workbench]    [FinCEN SAR Builder]  [Sanctions Screening]     [Hash Audit Verifier]|
+--------------------------------------------------------------------------------------------------+
                                                 |
                                    REST / JSON API (FastAPI)
                                  Bearer Token RBAC + Rate Limit
                                                 |
+--------------------------------------------------------------------------------------------------+
|                             API ROUTING & MIDDLEWARE LAYER (`app/api`)                           |
|  - Request ID & Structured Audit Logging Middleware                                              |
|  - Role-Based Access Control (L1_ANALYST, L2_INVESTIGATOR, QA_COMPLIANCE_OFFICER, RISK_ENGINEER) |
|  - Pydantic Schema Validation & Deterministic Error Envelopes                                    |
+--------------------------------------------------------------------------------------------------+
                                                 |
+--------------------------------------------------------------------------------------------------+
|                           CORE DOMAIN & APPLICATION SERVICES (`app/*`)                           |
|                                                                                                  |
|  +---------------------------+  +----------------------------+  +-----------------------------+  |
|  |   Typology Rule Engine    |  |   RuleForge Simulation     |  |  Heterogeneous Graph Engine |  |
|  |     (`app/typologies`)    |  |     (`app/simulation`)     |  |        (`app/graph`)        |  |
|  | - 25 AML/Fraud Evaluators |  | - Candidate Rule Cloning   |  | - K-Hop Ego Subgraphs       |  |
|  | - Windowed Aggregations   |  | - Confusion Matrix (TP/FP) |  | - Temporal Cycle Detection  |  |
|  | - Explainable Evidence    |  | - Precision/Recall/F1      |  | - Tarjan SCC & PageRank     |  |
|  +---------------------------+  +----------------------------+  +-----------------------------+  |
|                                                                                                  |
|  +---------------------------+  +----------------------------+  +-----------------------------+  |
|  | Composite KYC Risk Engine |  | Sanctions & PEP Screening  |  | Case, QA & SAR Narrative    |  |
|  |       (`app/risk`)        |  |     (`app/sanctions`)      |  |   (`app/cases`, `reporting`)|  |
|  | - 6-Factor Weighted Model |  | - Jaro-Winkler & Edit Dist |  | - 4-Eyes State Machine      |  |
|  | - Baseline Z-Score Drift  |  | - Soundex/Metaphone Match  |  | - FinCEN 5-W SAR Generator  |  |
|  | - Contagion Propagation   |  | - Token Set & DOB Weight   |  | - CTR Aggregation Filing    |  |
|  +---------------------------+  +----------------------------+  +-----------------------------+  |
+--------------------------------------------------------------------------------------------------+
                                                 |
+--------------------------------------------------------------------------------------------------+
|                   DATA ACCESS, MIGRATIONS & CRYPTOGRAPHIC AUDIT (`app/db`, `app/audit`)          |
|  - Repository Pattern over Parameterized SQL (Zero SQL Injection Surface)                        |
|  - Versioned Forward/Rollback Schema Migrations (`backend/migrations`)                           |
|  - Immutable SHA-256 + HMAC-SHA256 Chained Audit Ledger (`app/audit`)                            |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Module Boundaries & Responsibilities

### 2.1 `backend/app/core/` — Configuration, Security, Exceptions & Logging
- **`config.py`**: Loads environment variables with strict type conversion, sensible local defaults, and runtime validation.
- **`security.py`**: Implements password hashing (`PBKDF2-HMAC-SHA256` with 210,000 iterations and per-user cryptographic salt), stateless HMAC-SHA256 signed session tokens with expiration claims, and granular Role-Based Access Control (RBAC) permission matrices.
- **`exceptions.py`**: Hierarchy of domain exceptions (`AuthenticationError`, `AuthorizationError`, `ValidationError`, `ResourceNotFoundError`, `StateTransitionError`, `SeparationOfDutiesError`, `AuditIntegrityError`).
- **`logging_config.py`**: Structured JSON/key-value logging with correlation request IDs and sensitive PII masking filters.

### 2.2 `backend/app/db/` & `backend/migrations/` — Persistence & Schema Versioning
- **`connection.py`**: Thread-safe connection manager supporting SQLite in `WAL` (Write-Ahead Logging) mode with `FOREIGN KEY` enforcement enabled on every connection, plus seamless switching to PostgreSQL via connection URI.
- **`migrator.py`**: Deterministic schema migration runner tracking applied versions, SHA-256 checksums, and execution timestamps in `schema_migrations`.

### 2.3 `backend/app/typologies/` — The 25-Rule AML & Fraud Detection Engine
- Designed around the **Strategy and Registry Pattern**.
- Every typology detector inherits from `BaseTypologyDetector` and implements `evaluate_transaction(tx, context)` and `evaluate_batch(window_txs, context)`.
- Each triggered rule emits a structured `RuleTriggerResult` containing:
  - `rule_id`, `rule_name`, `typology_family`, `severity`, `confidence_score` (0–100)
  - `triggered_transaction_ids`
  - `quantitative_metrics` (e.g., cumulative cash total, pass-through ratio, velocity Z-score, fan-in sender count)
  - `human_readable_narrative` explaining the exact threshold breach for L1/L2 analysts.

### 2.4 `backend/app/graph/` — Multi-Hop Graph Forensics & Entity Resolution
- Builds an in-memory directed multigraph synchronized with the relational store.
- Supports two interconnected graph projections:
  1. **Monetary Flow Graph ($G_{flow}$)**: Directed weighted edges representing value transfers (`Account -> Account` or `Account -> Counterparty`) annotated with timestamp, USD amount, channel, and transaction ID.
  2. **Identity & Attribute Attribution Graph ($G_{attr}$)**: Bipartite connections linking `Customer` and `Account` nodes to shared attributes (`DeviceFingerprint`, `IPAddress`, `PhysicalAddress`, `PhoneNumber`, `TaxID`, `BeneficialOwner`).
- Implements pure-Python graph algorithms:
  - **Temporal Flow Pathfinding**: Finds chains $v_0 \xrightarrow{e_1} v_1 \xrightarrow{e_2} \dots \xrightarrow{e_k} v_k$ where $t(e_1) \le t(e_2) \le \dots \le t(e_k)$ within a configurable time horizon $\Delta T$.
  - **Circular / Carousel Flow Detection**: Detects directed cycles where funds return to the originator or a common beneficial owner after 2–6 hops.
  - **Tarjan's Strongly Connected Components (SCC)**: Isolates tightly coupled mule rings.
  - **Iterative PageRank & Hub/Authority HITS Scoring**: Ranks accounts by structural importance in illicit fund movement.

### 2.5 `backend/app/simulation/` — RuleForge Shadow-Mode Backtesting
- Executes candidate rule parameter sets against historical transactions without mutating production alert queues.
- Evaluates generated shadow alerts against ground-truth historical case dispositions (`SAR_FILED` = positive label; `CLOSED_FALSE_POSITIVE` = negative label).
- Outputs a full statistical comparison report including confusion matrix, precision, recall, F1, false-positive reduction rate, and estimated monthly analyst hours saved.

### 2.6 `backend/app/cases/` & `backend/app/reporting/` — Case Lifecycle & FinCEN SAR Engine
- Manages alert-to-case promotion, SLA countdowns, L1/L2 assignment, four-eyes QA sign-off, and FinCEN SAR/CTR generation.
- Validates that no SAR can transition to `SAR_FILED` without:
  1. At least one linked suspicious transaction.
  2. Complete subject KYC attribution.
  3. All 5 mandatory narrative sections (`WHO`, `WHAT`, `WHEN`, `WHERE`, `WHY_HOW`) passing minimum substantive length and regulatory keyword checks.
  4. QA Reviewer distinct from the Investigating Analyst (Four-Eyes principle).

---

## 3. Architectural Decision Records (ADRs)

### ADR-001: SQLite WAL Mode Default with Zero-Dependency Portability
- **Context:** Reviewers and developers on Windows/PowerShell and CI runners need to clone, run tests, seed realistic financial crime scenarios, and launch the full stack immediately without configuring Docker daemons or external cloud database credentials.
- **Decision:** Use SQLite3 with `PRAGMA journal_mode=WAL;` and `PRAGMA foreign_keys=ON;` as the default zero-configuration persistence engine, abstracted behind repository classes so PostgreSQL can be swapped in via configuration.
- **Consequences:** 100% deterministic local execution and instant test suite runs while maintaining strict relational integrity.

### ADR-002: Hybrid Relational + In-Memory Property Graph Engine
- **Context:** Dedicated graph databases (Neo4j, TigerGraph) require heavy JVM processes and external licenses.
- **Decision:** Store canonical nodes and edges in indexed relational tables (`graph_nodes`, `graph_edges`, `transactions`, `shared_attributes`) and hydrate a high-speed adjacency structure for multi-hop graph algorithms.
- **Consequences:** Zero external infrastructure dependencies, sub-50ms K-hop ego-network queries for up to 50,000 nodes, and complete transparency into graph traversal logic.

### ADR-003: Cryptographic Hash-Chained Audit Ledger
- **Context:** Regulatory compliance (FinCEN, FFIEC BSA/AML examination manual) requires proving that alert dispositions, risk score overrides, and SAR narratives were not retroactively altered.
- **Decision:** Chain every row in `audit_logs` using `HMAC-SHA256` over the previous entry's hash and current payload, paired with a `/api/v1/audit/verify` verification endpoint.
