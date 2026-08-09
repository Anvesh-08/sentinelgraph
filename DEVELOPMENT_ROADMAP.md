# SentinelGraph — Development Roadmap (`DEVELOPMENT_ROADMAP.md`)

---

## Completed Milestones (v1.0.0)
- [x] **Phase 1 — Product Discovery & Specification:** Domain problem definition, persona mapping, 25-rule typology catalog, and regulatory SAR workflow specification (`PRODUCT_SPEC.md`).
- [x] **Phase 2 — System & Database Architecture:** Layered modular monolith architecture, 15-table normalized schema with WAL concurrency, RBAC matrix, and cryptographic audit chain design (`ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, `API_DOCUMENTATION.md`).
- [x] **Phase 3 — Core Foundation & Persistence:** Database connection manager, automated migration runner, PBKDF2/HMAC security core, structured audit ledger, and domain models/repositories.
- [x] **Phase 4 — Core AML/Fraud Engines & Investigator Workbench:**
  - [x] 6-Factor Dynamic KYC/KYB Composite Risk Engine.
  - [x] Multi-Algorithm Fuzzy Sanctions & PEP Screening Engine.
  - [x] 25 Configurable AML & Fraud Typology Detectors across 5 families.
  - [x] Heterogeneous Multi-Hop Graph Engine (Ego networks, Temporal paths, Cycles, Tarjan SCC, PageRank, Shared-PII rings).
  - [x] RuleForge Shadow-Mode Backtesting & Confusion Matrix Simulation Engine.
  - [x] Four-Eyes Case Management & Automated FinCEN 5-W SAR Narrative Generator.
  - [x] Synthetic Financial Crime Scenario Generator (12 realistic typologies + baseline traffic).
  - [x] Interactive Single-Page Investigator Workbench UI & REST API.
- [x] **Phase 5 & 6 — Verification, CI/CD & Release Readiness:** Comprehensive unit, integration, and E2E test suites, GitHub Actions CI workflows, issue/PR templates, and full documentation verification.

---

## Future Roadmap (v1.1 – v2.0)
- **v1.1 — ISO 20022 (`pacs.008` / `pain.001`) XML Native Ingestion Parser:** Direct streaming ingestion of SWIFT MX XML messages with structured party postal address extraction.
- **v1.2 — FinCEN BSA E-Filing XML Batch Exporter:** Export approved SAR and CTR batches directly into the FinCEN BSA Electronic Filing XML schema.
- **v1.3 — Graph Feature Extraction for Gradient Boosted Alert Prioritization:** Combine deterministic typology triggers with topological graph features (clustering coefficient, PageRank delta, 2-hop risk contagion) to rank L1 alert queues.
- **v2.0 — Distributed Streaming Worker Mode:** Optional Kafka/Redis consumer workers for horizontal partitioning across multi-million daily transaction volumes.
