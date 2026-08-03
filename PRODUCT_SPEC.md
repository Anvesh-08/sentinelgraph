# SentinelGraph — Product Specification (`PRODUCT_SPEC.md`)

**Document Version:** 1.0.0  
**Status:** Approved & Implemented  
**Domain:** Financial Crime Prevention, AML/KYC Compliance, Transaction Monitoring, Graph Forensics, and Regulatory Reporting  

---

## 1. Executive Summary & Problem Statement

Financial institutions, payment facilitators (PayFacs), regional banks, and digital asset platforms face an acute operational bottleneck in Anti-Money Laundering (AML) and fraud operations:

1. **Fragmented Investigation Data:** L1 and L2 fraud/AML investigators spend 65–80% of their triage time gathering basic context across disconnected SQL databases, static KYC onboarding spreadsheets, wire/ACH logs, and device/IP telemetry before they can even evaluate an alert.
2. **Blind Rule Deployment (No Shadow-Mode Backtesting):** Compliance engineers frequently modify rule thresholds (e.g., lowering structuring limits from $9,500 to $8,500 or tightening velocity windows) directly in production without empirical simulation. This either floods analyst queues with false positives (>92% false-positive rates are routine) or creates blind spots that miss coordinated smurfing, layering, and mule-ring typologies.
3. **Inability to Detect Multi-Hop Network Typologies:** Row-based SQL transaction monitoring checks isolated account activity. Sophisticated financial crime operates across multi-hop graphs—such as fan-out smurfing rings, fan-in aggregation accounts, circular round-tripping, and shared physical hardware/IP clusters across ostensibly unrelated KYC profiles.
4. **Manual, Error-Prone SAR & Audit Workflows:** Generating FinCEN-aligned Suspicious Activity Reports (SARs) and Currency Transaction Reports (CTRs) requires manual narrative assembly, often lacking cryptographic chain-of-custody verification for regulatory examinations.

**SentinelGraph** solves these challenges by unifying **Real-Time & Batch AML Typology Detection**, **Shadow-Mode Rule Backtesting**, **Multi-Hop Entity & Flow Graph Forensics**, **Four-Eyes Case Management**, and **Structured SAR/CTR Regulatory Reporting** inside an independently owned, privacy-first, self-hosted platform.

---

## 2. Target User Personas

| Persona | Role & Responsibilities | Core Pain Points | SentinelGraph Value Proposition |
| :--- | :--- | :--- | :--- |
| **L1 Alert Triage Analyst** | Reviews incoming high-volume transaction monitoring alerts; performs initial KYC/transaction reconciliation; clears false positives or escalates suspicious behavior. | Slow context switching across 5+ internal tools; repetitive manual lookup of 30/90-day baselines. | Single-pane alert workbench showing exact rule trigger evidence, customer KYC risk breakdown, counterparty history, and 1-click false-positive disposition with mandatory reason codes. |
| **L2 Senior Forensic Investigator** | Conducts deep-dive investigations on escalated cases; traces multi-hop fund movements; uncovers money mule networks and beneficial ownership links; drafts SAR narratives. | Cannot visualize multi-hop pass-through chains or hidden device/IP/address overlaps across accounts. | Interactive multi-hop graph analyzer (BFS/DFS cycle & flow tracing, Tarjan SCC detection, PageRank centrality, shared attribute clustering) + structured FinCEN SAR 5-W narrative builder. |
| **QA / Compliance Officer (BSA Officer)** | Reviews L2 investigations before regulatory filing; enforces four-eyes review; approves SARs/CTRs; manages regulatory examinations. | Lack of tamper-evident audit logs; inconsistent SAR narratives missing mandatory regulatory fields. | Cryptographically chained SHA-256 + HMAC-SHA256 audit ledger, SLA breach trackers, and automated SAR completeness validation prior to filing. |
| **AML Risk & Quantitative Engineer** | Authors, tunes, and maintains transaction monitoring rules and composite KYC risk models. | Cannot measure precision/recall or alert volume impact before activating a rule change in production. | **RuleForge Shadow-Mode Backtesting Engine**: run candidate rules against historical labeled transactions to compute precision, recall, F1, false-positive delta, and confusion matrices before promotion. |

---

## 3. Competitive Landscape & Differentiation

| Capability | Legacy Enterprise Suites (Actimize, Mantas) | Cloud API Point Solutions | Toy Open-Source Scripts | **SentinelGraph** |
| :--- | :--- | :--- | :--- | :--- |
| **Deployment & Ownership** | Multi-million-dollar proprietary lock-in | External SaaS data-sharing risk | Incomplete single-script notebooks | **100% Self-Hosted, Independently Owned, Zero External API Lock-in** |
| **Typology Coverage** | 15–30 black-box rules | Basic velocity/webhook rules | 2–3 threshold checks | **25+ Transparent, Configurable AML/Fraud Typology Evaluators** |
| **Graph Network Forensics** | Expensive separate add-on module | Rare or limited to 1-hop | Static networkx plots | **Built-in Multi-Hop Flow, Cycle, Mule-Ring & Shared-PII Graph Engine** |
| **Shadow-Mode Backtesting** | Requires separate staging cluster | Limited historical replay | None | **Native Side-by-Side Production vs. Candidate Rule Simulation** |
| **Case & SAR Lifecycle** | Rigid, outdated UI | Basic webhook ticket | None | **Full L1 -> L2 -> QA -> SAR/CTR State Machine with Five-W Narrative Engine** |
| **Audit Trail Integrity** | Standard DB table | Standard logs | None | **Tamper-Evident Cryptographic Hash-Chained Ledger** |

---

## 4. Functional Requirements & Feature Catalogue

### 4.1 Customer KYC, KYB & Dynamic Composite Risk Scoring (`FR-RISK`)
- **FR-RISK-01:** Maintain comprehensive `Customer` profiles supporting both Retail (`INDIVIDUAL`) and Corporate (`BUSINESS` / KYB) entities, including occupation/industry NAICS code, country of residence, nationality, onboarding date, expected monthly volume, PEP (Politically Exposed Person) status, and adverse media flags.
- **FR-RISK-02:** Support `BeneficialOwner` records linked to business entities with ownership percentages, control prongs, and cross-customer identity linking.
- **FR-RISK-03:** Compute deterministic, explainable **Composite Risk Scores (0–100)** across six weighted dimensions:
  1. Geographic Risk (FATF high-risk/grey-list jurisdictions, offshore tax havens, sanctions proximity).
  2. Customer/Entity Type & Ownership Complexity (shell structures, cash-intensive businesses, NGOs, MSBs).
  3. PEP, Sanctions & Adverse Media Exposure.
  4. Product & Channel Risk (wire, cross-border ACH, crypto ramps, P2P, cash deposits).
  5. Behavioral & Transactional Velocity Deviation (30-day vs. 90-day historical baseline Z-score).
  6. Graph Network Contagion Risk (1-hop and 2-hop exposure to flagged accounts or SAR subjects).
- **FR-RISK-04:** Automatically classify customers into `LOW` (0–34.9), `MEDIUM` (35.0–64.9), `HIGH` (65.0–84.9), and `CRITICAL` (85.0–100.0) bands and record historical risk score snapshots whenever recalculations occur.

### 4.2 Watchlist, Sanctions & PEP Fuzzy Screening Engine (`FR-SANC`)
- **FR-SANC-01:** Screen customer names, aliases, counterparties, and beneficial owners against consolidated watchlists (OFAC SDN simulated entries, UN Consolidated List patterns, EU Financial Sanctions, PEP registries, and Adverse Media feeds).
- **FR-SANC-02:** Implement multi-algorithm string similarity and phonetic matching:
  - Jaro-Winkler similarity (optimized for name prefixes and transliteration variants).
  - Normalized Levenshtein edit distance.
  - Token-sort and token-set ratio (handles inverted name order such as `"GOMEZ CARLOS"` vs. `"Carlos Gomez"`).
  - Double-Metaphone / Soundex phonetic encoding (catches phonetic spellings like `"KHALID"` vs. `"KHALED"`).
  - Date-of-birth and jurisdiction corroboration weighting.
- **FR-SANC-03:** Support analyst hit disposition (`TRUE_MATCH`, `FALSE_POSITIVE`, `POTENTIAL_MATCH_ESCALATED`) with mandatory justification notes and suppression allowlisting for verified false positives.

### 4.3 Multi-Channel Transaction Ingestion & Normalization (`FR-INGEST`)
- **FR-INGEST-01:** Ingest and validate transactions across channels: `CASH_DEPOSIT`, `CASH_WITHDRAWAL`, `WIRE_DOMESTIC`, `WIRE_INTERNATIONAL`, `ACH_CREDIT`, `ACH_DEBIT`, `CARD_POS`, `CARD_ECOMMERCE`, `INTERNAL_TRANSFER`, and `CRYPTO_EXCHANGE`.
- **FR-INGEST-02:** Normalize multi-currency amounts into USD base equivalents using deterministic FX rates while preserving original currency, exchange rate, IP address, device fingerprint ID, geolocation coordinates, merchant category code (MCC), and counterparty bank/BIC details.
- **FR-INGEST-03:** Provide a deterministic **Synthetic Financial Crime & Baseline Scenario Generator** capable of seeding realistic background customer traffic interleaved with 12 distinct embedded criminal topologies (smurfing rings, pass-through mule chains, circular trade-based layering, elder financial exploitation, account takeover + rapid drain, shell-company payroll fraud, etc.).

### 4.4 Configurable AML & Fraud Typology Engine (`FR-RULE`)
Implement **25 production-grade typology detectors** organized into 5 typology families:
- **Family A — Cash Structuring & CTR Evasion:**
  1. `AML-STR-001`: Classic Single-Account Sub-CTR Cash Structuring ($8,000–$9,999.99 repeated cash deposits).
  2. `AML-STR-002`: Rolling 24-Hour / 72-Hour Cumulative Cash Aggregation Exceeding $10,000 across multiple branches/ATMs.
  3. `AML-STR-003`: Coordinated Multi-Depositor Smurfing (Fan-In sub-threshold cash deposits into a single beneficiary account).
  4. `AML-STR-004`: Sequential Just-Under-Threshold Wire/ACH Splits (breaking a large transfer into multiple $2,900–$4,950 transfers to evade Travel Rule / recordkeeping thresholds).
  5. `AML-STR-005`: Round-Dollar Cash Deposit Anomaly (high frequency of exact $1,000 / $5,000 denomination deposits inconsistent with retail business profile).
- **Family B — Rapid Movement of Funds, Layering & Pass-Through:**
  6. `AML-LAY-001`: High-Velocity Pass-Through / Conduit Account (85%–100% of inbound funds wired out within 24 hours).
  7. `AML-LAY-002`: Multi-Hop Layering Chain (funds moving A -> B -> C -> D within 48 hours with minimal retention).
  8. `AML-LAY-003`: Circular Round-Tripping / Carousel Flow (funds returning to the originator or affiliated entity through 3+ intermediaries).
  9. `AML-LAY-004`: Dormant-to-Active Sudden Awakening (account inactive for 90+ days suddenly receiving and disbursing high-value transfers).
  10. `AML-LAY-005`: Immediate Cross-Channel Conversion (fiat wire/ACH inbound immediately converted to external crypto/offshore wire).
- **Family C — Mule Networks, Fan-In / Fan-Out & Graph Anomalies:**
  11. `AML-NET-001`: Fan-In Aggregation Hub (10+ distinct unrelated senders transferring funds to a single collector account in a short window).
  12. `AML-NET-002`: Fan-Out Distribution Hub / Payroll Mule (single account dispersing funds to 10+ unrelated recipients immediately after funding).
  13. `AML-NET-003`: Shared Device / IP / Tax-ID Ring (multiple ostensibly unrelated accounts sharing identical hardware fingerprints, IP subnets, or phone numbers while transacting).
  14. `AML-NET-004`: High Graph Centrality / Bridge Node Contagion (transacting directly with a known SAR subject or frozen account).
  15. `AML-NET-005`: Reciprocal Back-and-Forth Wash Transfers between two accounts with no apparent economic purpose.
- **Family D — Geographic, Corridor & Sanctions Evasion:**
  16. `AML-GEO-001`: High-Risk / FATF Grey-or-Black-List Corridor Wire Transfer.
  17. `AML-GEO-002`: Offshore Tax-Haven Shell Company Layering (transfers involving BVI, Cayman, Panama, Seychelles, etc. without commercial invoice justification).
  18. `AML-GEO-003`: Impossible Travel / Geolocation Velocity Conflict (card/login activity from two distant countries within an impossible travel timeframe).
  19. `AML-GEO-004`: High-Risk Border/Corridor Remittance Spike exceeding customer's stated KYC geographic footprint.
  20. `AML-GEO-005`: Sanctions-Adjacent Jurisdiction Routing (routing transactions through border hubs known for sanctions circumvention).
- **Family E — Behavioral Anomalies, Account Takeover (ATO) & Commercial Fraud:**
  21. `FRD-BEH-001`: Extreme Z-Score Transaction Amount Spike (>3.5 standard deviations above customer's 90-day mean and >3x stated KYC expected monthly volume).
  22. `FRD-BEH-002`: Account Takeover (ATO) New Device + New Beneficiary + Rapid Balance Drain (>75% of account balance).
  23. `FRD-BEH-003`: Elder / Vulnerable Customer Sudden Outflow Spike (unusual large wires/cash withdrawals from senior accounts).
  24. `FRD-BEH-004`: Business Profile Mismatch / Shell Company Activity (high-volume non-commercial P2P/luxury MCC spend on a B2B logistics/consulting account).
  25. `FRD-BEH-005`: Smurfing + Midnight/Off-Hours Automated Scripting Burst (high-frequency micro-transactions occurring between 01:00 and 04:30 local time).

### 4.5 Shadow-Mode Rule Backtesting & Simulation Studio (`FR-SIM`)
- **FR-SIM-01:** Allow risk engineers to clone any active production rule, adjust parameter thresholds (e.g., `min_amount`, `window_hours`, `min_count`, `pass_through_ratio`), and execute a **Shadow-Mode Backtest** over any historical date range.
- **FR-SIM-02:** Compare baseline rule performance against candidate parameters using ground-truth case outcomes (`SAR_FILED` / `CONFIRMED_FRAUD` vs. `FALSE_POSITIVE`).
- **FR-SIM-03:** Compute and persist detailed simulation metrics: True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision, Recall, F1-Score, Alert Volume Delta (%), Estimated Analyst Hours Saved/Added, and a sample diff of newly captured vs. dropped alerts.

### 4.6 Multi-Hop Graph Investigation & Link Analysis (`FR-GRAPH`)
- **FR-GRAPH-01:** Construct a unified heterogeneous property graph containing nodes for `Customer`, `Account`, `Counterparty`, `Device`, `IPAddress`, `PhysicalAddress`, `Phone`, and `BeneficialOwner`.
- **FR-GRAPH-02:** Provide graph traversal algorithms:
  - K-Hop Ego Network extraction around any customer or account.
  - Shortest path & all simple paths of funds between any two entities.
  - Cycle / Circular flow detection (Johnson/DFS cycle enumeration with temporal ordering constraints: $t_1 < t_2 < \dots < t_k$).
  - Strongly Connected Components (Tarjan's algorithm) and Weakly Connected Components.
  - Simplified PageRank & Degree/Betweenness centrality scoring to identify hub mule accounts.
  - Shared-Attribute Entity Resolution clustering (detecting synthetic identities or coordinated rings sharing devices, IPs, addresses, or phone numbers).

### 4.7 Case Management, Four-Eyes Workflow & SAR/CTR Generator (`FR-CASE`)
- **FR-CASE-01:** Enforce a strict state machine for Cases:
  `OPEN` -> `IN_REVIEW_L1` -> `ESCALATED_L2` -> `PENDING_QA_APPROVAL` -> `SAR_APPROVED` -> `SAR_FILED` (or `CLOSED_FALSE_POSITIVE` / `CLOSED_NO_SAR`).
- **FR-CASE-02:** Enforce **Four-Eyes Separation of Duties**: the investigator who escalates or recommends a SAR cannot be the same user who approves and files the SAR in QA review (unless explicitly overridden by a `SYSTEM_ADMIN` in emergency mode with audit logging).
- **FR-CASE-03:** Support attaching evidence items (transactions, graph snapshots, KYC snapshots, analyst notes, external document hashes) to a case locker.
- **FR-CASE-04:** Automatically generate structured **FinCEN-Compliant SAR Narratives** organized into the industry-standard **Five Ws + How** sections:
  1. **Executive Summary & Alert Trigger Context**
  2. **WHO** (Subject KYC Profile, Beneficial Ownership, Risk Score, Prior SAR History)
  3. **WHAT** (Instruments, Channels, Total Suspicious Dollar Volume, Counterparties)
  4. **WHEN** (Activity Date Range, Velocity Patterns, Timeline of Key Events)
  5. **WHERE** (Geographic Jurisdictions, Branches, IP/Device Locations, High-Risk Corridors)
  6. **WHY & HOW** (Detailed Typology Mechanics, Structuring/Layering/Graph Evidence, Deviation from Expected KYC Baseline)
  7. **Supporting Evidence Appendix & Verification Checksum**

---

## 5. Non-Functional Requirements (`NFR`)
- **Security & Zero-Secret Footprint:** Zero hardcoded API keys, credentials, or external proprietary dependencies. Password hashing via PBKDF2-HMAC-SHA256 (210,000 iterations) and signed stateless HMAC-SHA256 bearer tokens with role-based permissions.
- **Tamper-Evident Auditability:** Every mutating operation writes an immutable record to `audit_logs` containing `previous_hash` and `entry_hash = HMAC_SHA256(previous_hash | timestamp | actor_id | action | entity_type | entity_id | payload_json)`.
- **Portability:** Runs out-of-the-box on Windows (PowerShell / VS Code), macOS, and Linux using Python 3.11+ and SQLite (with zero-config WAL mode concurrency) or PostgreSQL.
