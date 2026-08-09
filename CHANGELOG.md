# Changelog (`CHANGELOG.md`)

All notable engineering changes to **SentinelGraph** are documented in this file.

## [1.0.0] — 2026-11-10
### Added
- **Core Persistence & Migrations:** Implemented SQLite WAL / PostgreSQL connection layer and deterministic migration runner (`001_initial_core_schema.sql`, `002_seed_reference_rules.sql`).
- **Security & Cryptographic Audit Ledger:** Added PBKDF2-HMAC-SHA256 password hashing, signed HMAC-SHA256 bearer tokens, 5-role RBAC enforcement, and tamper-evident hash-chained `audit_logs`.
- **Composite KYC/KYB Risk Engine:** Implemented 6-dimension customer risk calculator covering geographic, entity, PEP/sanctions, channel, velocity Z-score, and graph contagion risk.
- **Sanctions & PEP Fuzzy Screener:** Implemented Jaro-Winkler, Levenshtein, Token-Set, and Soundex phonetic screening with DOB/country corroboration.
- **25-Rule AML & Fraud Typology Engine:** Built 5 typology detector families (Cash Structuring, Rapid Layering, Mule Network Graph Anomalies, Geographic/Corridor Risk, and Behavioral/ATO Fraud).
- **Multi-Hop Graph Forensics Engine:** Implemented K-hop ego network extraction, temporal fund-flow pathfinding, cycle detection, Tarjan's Strongly Connected Components, PageRank centrality, and shared-attribute ring resolution.
- **RuleForge Shadow-Mode Backtesting Studio:** Built historical rule simulation engine computing TP, FP, TN, FN, Precision, Recall, F1, and alert volume delta.
- **Four-Eyes Case Management & FinCEN SAR Generator:** Implemented L1 -> L2 -> QA state machine with strict separation-of-duties validation and automated 5-W narrative generation.
- **Synthetic Financial Crime Seeder & CLI:** Added deterministic scenario generator seeding realistic customers, accounts, watchlists, and 12 embedded financial crime topologies.
- **Investigator Web Workbench & Test Suite:** Built FastAPI REST server, interactive frontend workbench, and comprehensive unit, integration, and E2E test suites.
