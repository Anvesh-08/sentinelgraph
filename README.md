# SentinelGraph — Enterprise AML Transaction Monitoring, Shadow-Mode Rule Backtesting & Graph Investigation Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](pyproject.toml)
[![Architecture: Modular Monolith + Graph](https://img.shields.io/badge/Architecture-Modular_Monolith_%2B_Graph-2ea44f.svg)](ARCHITECTURE.md)

**SentinelGraph** is an independently owned, full-stack Anti-Money Laundering (AML), Know Your Customer/Business (KYC/KYB), Shadow-Mode Rule Backtesting (`RuleForge`), Multi-Hop Graph Forensics, and FinCEN SAR Compliance Workbench.

Designed from real-world financial crime investigation workflows, SentinelGraph bridges the gap between **quantitative rule engineering** and **L1/L2/QA forensic case investigations** without external cloud lock-in or third-party API dependencies.

---

## Key Capabilities

1. **25 Configurable AML & Fraud Typology Detectors (`backend/app/typologies/`)**:
   - **Family A (Cash Structuring & CTR Evasion):** Sub-CTR cash deposits ($8,000–$9,999.99), rolling 24h/72h multi-branch cash aggregation, fan-in smurfing deposits, sequential sub-Travel-Rule wire splits, and round-dollar cash anomalies.
   - **Family B (Rapid Layering & Pass-Through):** High-velocity conduit pass-throughs (85%+ outbound within 24h), multi-hop layering chains, circular round-tripping, dormant account sudden awakening, and immediate cross-channel fiat-to-crypto conversion.
   - **Family C (Mule Networks & Graph Anomalies):** Fan-in collector hubs, fan-out payroll/mule distributors, shared hardware/IP/phone/Tax-ID identity rings, high-centrality bridge node contagion, and reciprocal wash transfers.
   - **Family D (Geographic & Sanctions Evasion):** FATF high-risk/black-list corridor wires, offshore tax-haven shell company transfers, impossible travel velocity conflicts, border remittance spikes, and sanctions-adjacent routing.
   - **Family E (Behavioral Anomalies & ATO Fraud):** Extreme 90-day Z-score spikes (>3.5$\sigma$), new-device + new-beneficiary rapid balance drain (ATO), vulnerable/senior account sudden outflow spikes, KYB business profile MCC mismatch, and midnight automated scripting bursts.

2. **Multi-Hop Heterogeneous Graph Forensics Engine (`backend/app/graph/`)**:
   - Extracts K-Hop Ego Networks across accounts, customers, counterparties, devices, IP addresses, physical addresses, and Ultimate Beneficial Owners (UBOs).
   - Implements pure-Python **Temporal Fund-Flow Pathfinding**, **Directed Cycle / Carousel Enumeration**, **Tarjan's Strongly Connected Components (SCC)**, **Iterative PageRank & Hub/Authority Scoring**, and **Shared-PII Ring Clustering**.

3. **RuleForge Shadow-Mode Backtesting Studio (`backend/app/simulation/`)**:
   - Lets risk engineers simulate candidate rule threshold changes against historical labeled transactions before promoting rules to production.
   - Computes **True Positives (TP)**, **False Positives (FP)**, **True Negatives (TN)**, **False Negatives (FN)**, **Precision**, **Recall**, **F1-Score**, **Alert Volume Delta (%)**, and **Estimated Analyst Hours Saved**.

4. **Dynamic 6-Factor KYC/KYB Composite Risk & Fuzzy Sanctions Screening (`backend/app/risk/`, `backend/app/sanctions/`)**:
   - Evaluates Geographic, Entity/UBO Complexity, PEP/Sanctions, Channel, Behavioral Velocity Z-Score, and Graph Contagion risk into explainable `0–100` scores (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - Screens names against OFAC/UN/EU/PEP watchlists using **Jaro-Winkler**, **Levenshtein Edit Distance**, **Token-Set Ratio**, and **Double-Metaphone/Soundex** phonetic encoding.

5. **Four-Eyes Case Management & Automated FinCEN 5-W SAR Generator (`backend/app/cases/`, `backend/app/reporting/`)**:
   - Enforces `OPEN -> IN_REVIEW_L1 -> ESCALATED_L2 -> PENDING_QA_APPROVAL -> SAR_APPROVED -> SAR_FILED` with strict **Four-Eyes Separation of Duties** (an investigator cannot QA-approve their own case).
   - Generates structured FinCEN-aligned Suspicious Activity Report narratives (`WHO`, `WHAT`, `WHEN`, `WHERE`, `WHY & HOW`) with SHA-256 content verification.

6. **Tamper-Evident Cryptographic Audit Ledger (`backend/app/audit/`)**:
   - Every state mutation is chained with `HMAC-SHA256(previous_hash | timestamp | actor | action | entity | payload)` and verified via `/api/v1/audit/verify`.

---

## Quick Start (Windows PowerShell / VS Code & Linux/macOS)

### 1. Clone & Set Up Virtual Environment (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

### 2. Initialize Database, Run Migrations & Seed Realistic Financial Crime Scenarios
```powershell
python -m backend.app.cli.main init-db --seed
```

### 3. Run the Automated Verification & Test Suite
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 4. Launch the Full-Stack SentinelGraph Server & Investigator Workbench UI
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open **`http://127.0.0.1:8000`** in your browser to access the interactive Investigator Workbench, or **`http://127.0.0.1:8000/docs`** for the interactive OpenAPI specification.

---

## Documentation Index
- [`PRODUCT_SPEC.md`](PRODUCT_SPEC.md) — Product requirements, personas, and 25-rule typology catalog.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Layered architecture, component boundaries, and ADRs.
- [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md) — Full ERD and 15-table relational/graph schema specification.
- [`API_DOCUMENTATION.md`](API_DOCUMENTATION.md) — REST API endpoints, payloads, and RBAC permission matrix.
- [`SECURITY.md`](SECURITY.md) — Cryptographic standards, PBKDF2/HMAC auth, and audit chain integrity.
- [`TESTING.md`](TESTING.md) — Unit, integration, and E2E testing strategy and boundary test scenarios.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Engineering workflow, branching standards, and code review guidelines.
- [`DEVELOPMENT_ROADMAP.md`](DEVELOPMENT_ROADMAP.md) — Completed phases and v1.1–v2.0 engineering roadmap.
- [`CHANGELOG.md`](CHANGELOG.md) — Versioned release notes.

<!-- Release v2.0.0 Verified -->
