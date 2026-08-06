# SentinelGraph — Database Schema Specification (`DATABASE_SCHEMA.md`)

**Database Engine:** SQLite 3 (WAL Mode, `foreign_keys = ON`) / PostgreSQL 15+ Compatible  
**Migration Versioning:** Managed via `backend/migrations/` and tracked in `schema_migrations`  

---

## 1. Entity-Relationship Diagram (ERD)

```
+-------------------+       1:N       +--------------------+       1:N       +---------------------+
|     customers     |---------------->|      accounts      |---------------->|    transactions     |
|-------------------|                 |--------------------|                 |---------------------|
| id (PK)           |                 | id (PK)            |                 | id (PK)             |
| external_ref (UQ) |                 | customer_id (FK)   |                 | external_tx_id (UQ) |
| customer_type     |                 | account_number(UQ) |                 | account_id (FK)     |
| legal_name        |                 | account_type       |                 | counterparty_id(FK) |
| country_code      |                 | currency           |                 | tx_type / channel   |
| risk_score        |                 | current_balance    |                 | direction           |
| risk_band         |                 | status             |                 | amount_usd          |
| pep_flag          |                 | opened_at          |                 | device_id / ip_addr |
+-------------------+                 +--------------------+                 +---------------------+
         |                                      |                                       |
         | 1:N                                  | 1:N                                   | M:N
         v                                      v                                       v
+-------------------+                 +--------------------+                 +---------------------+
| beneficial_owners |                 |      alerts        |<----------------|  alert_transactions |
|-------------------|                 |--------------------|                 |---------------------|
| id (PK)           |                 | id (PK)            |                 | alert_id (FK)       |
| customer_id (FK)  |                 | alert_ref (UQ)     |                 | transaction_id (FK) |
| full_name         |                 | customer_id (FK)   |                 | contribution_weight |
| ownership_pct     |                 | account_id (FK)    |                 +---------------------+
| is_pep            |                 | rule_id (FK)       |
+-------------------+                 | severity / score   |
                                      | status / assigned  |
                                      | case_id (FK)       |
                                      +--------------------+
                                                |
                                                | N:1
                                                v
+-------------------+       1:N       +--------------------+       1:N       +---------------------+
|       users       |---------------->|       cases        |---------------->|     sar_reports     |
|-------------------|                 |--------------------|                 |---------------------|
| id (PK)           |                 | id (PK)            |                 | id (PK)             |
| username (UQ)     |                 | case_number (UQ)   |                 | sar_ref (UQ)        |
| email (UQ)        |                 | primary_customer_id|                 | case_id (FK)        |
| role              |                 | status / priority  |                 | subject_customer_id |
| password_hash     |                 | investigator_id(FK)|                 | total_suspicious_usd|
+-------------------+                 | qa_reviewer_id (FK)|                 | narrative_five_ws   |
                                      | disposition        |                 | filing_status       |
                                      +--------------------+                 +---------------------+
```

---

## 2. Table Definitions

### 2.1 `schema_migrations`
Tracks applied DDL migrations and verifies checksum integrity.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `version` | `TEXT` | `PRIMARY KEY` | Migration version identifier (e.g., `001_initial_core_schema`) |
| `name` | `TEXT` | `NOT NULL` | Human-readable migration title |
| `checksum` | `TEXT` | `NOT NULL` | SHA-256 hash of the SQL migration content |
| `applied_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.2 `users`
Stores platform operators, analysts, investigators, QA officers, and risk engineers.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `username` | `TEXT` | `UNIQUE NOT NULL` | Login username |
| `email` | `TEXT` | `UNIQUE NOT NULL` | Corporate email address |
| `full_name` | `TEXT` | `NOT NULL` | Full display name |
| `role` | `TEXT` | `NOT NULL` | `L1_ANALYST`, `L2_INVESTIGATOR`, `QA_COMPLIANCE_OFFICER`, `RISK_ENGINEER`, `SYSTEM_ADMIN` |
| `password_hash` | `TEXT` | `NOT NULL` | PBKDF2-HMAC-SHA256 hash |
| `password_salt` | `TEXT` | `NOT NULL` | Hex-encoded 16-byte random salt |
| `is_active` | `INTEGER` | `NOT NULL DEFAULT 1` | `1` = active, `0` = disabled |
| `last_login_at` | `TEXT` | `NULL` | ISO-8601 UTC timestamp |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.3 `customers`
Stores Retail (`INDIVIDUAL`) and Corporate (`BUSINESS`) KYC/KYB profiles.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `external_ref` | `TEXT` | `UNIQUE NOT NULL` | External core banking CIF ID (e.g., `CUST-100042`) |
| `customer_type` | `TEXT` | `NOT NULL` | `INDIVIDUAL` or `BUSINESS` |
| `legal_name` | `TEXT` | `NOT NULL` | Full legal name or corporate entity name |
| `date_of_birth_or_inc` | `TEXT` | `NOT NULL` | YYYY-MM-DD birth or incorporation date |
| `nationality_or_reg_country` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 country code |
| `residence_country` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 country code |
| `occupation_or_industry` | `TEXT` | `NOT NULL` | Occupation or industry sector |
| `naics_code` | `TEXT` | `NULL` | 6-digit industry classification |
| `tax_id_hash` | `TEXT` | `NOT NULL` | SHA-256 hash of SSN/EIN/TIN for privacy-preserving linkage |
| `email` | `TEXT` | `NULL` | Contact email |
| `phone_number` | `TEXT` | `NULL` | Normalized E.164 phone number |
| `physical_address` | `TEXT` | `NULL` | Standardized physical address |
| `expected_monthly_volume_usd` | `REAL` | `NOT NULL DEFAULT 5000.0` | Stated KYC expected monthly volume |
| `pep_flag` | `INTEGER` | `NOT NULL DEFAULT 0` | Politically Exposed Person indicator |
| `adverse_media_flag` | `INTEGER` | `NOT NULL DEFAULT 0` | Adverse media hit indicator |
| `sanctions_status` | `TEXT` | `NOT NULL DEFAULT 'CLEAR'` | `CLEAR`, `POTENTIAL_MATCH`, `CONFIRMED_MATCH` |
| `kyc_verification_level` | `TEXT` | `NOT NULL DEFAULT 'STANDARD'` | `SIMPLIFIED`, `STANDARD`, `ENHANCED_DUE_DILIGENCE` |
| `composite_risk_score` | `REAL` | `NOT NULL DEFAULT 15.0` | 0.0 to 100.0 calculated risk score |
| `risk_band` | `TEXT` | `NOT NULL DEFAULT 'LOW'` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `onboarding_date` | `TEXT` | `NOT NULL` | ISO-8601 date |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |
| `updated_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.4 `beneficial_owners`
Stores Ultimate Beneficial Owners (UBOs) and control persons for KYB corporate entities.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `customer_id` | `TEXT` | `NOT NULL REFERENCES customers(id)` | Corporate parent customer |
| `linked_individual_customer_id` | `TEXT` | `NULL REFERENCES customers(id)` | Optional link if UBO is also a retail customer |
| `full_name` | `TEXT` | `NOT NULL` | UBO legal name |
| `nationality` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 country code |
| `residence_country` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 country code |
| `date_of_birth` | `TEXT` | `NOT NULL` | YYYY-MM-DD |
| `ownership_percentage` | `REAL` | `NOT NULL` | 0.0 to 100.0 |
| `is_control_person` | `INTEGER` | `NOT NULL DEFAULT 0` | Control prong flag |
| `is_pep` | `INTEGER` | `NOT NULL DEFAULT 0` | PEP status |
| `tax_id_hash` | `TEXT` | `NOT NULL` | Hashed identifier for graph cross-linking |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.5 `accounts`
Stores deposit, checking, commercial treasury, card, and virtual wallet accounts.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `customer_id` | `TEXT` | `NOT NULL REFERENCES customers(id)` | Owning customer |
| `account_number` | `TEXT` | `UNIQUE NOT NULL` | Standardized account number |
| `account_type` | `TEXT` | `NOT NULL` | `CHECKING`, `SAVINGS`, `COMMERCIAL_TREASURY`, `MERCHANT_SETTLEMENT`, `CRYPTO_WALLET` |
| `currency` | `TEXT` | `NOT NULL DEFAULT 'USD'` | ISO-4217 currency code |
| `current_balance_usd` | `REAL` | `NOT NULL DEFAULT 0.0` | Current ledger balance in USD |
| `average_30d_balance_usd` | `REAL` | `NOT NULL DEFAULT 0.0` | Rolling 30-day average balance |
| `status` | `TEXT` | `NOT NULL DEFAULT 'ACTIVE'` | `ACTIVE`, `DORMANT`, `RESTRICTED`, `FROZEN`, `CLOSED` |
| `opened_at` | `TEXT` | `NOT NULL` | ISO-8601 timestamp |
| `last_activity_at` | `TEXT` | `NULL` | ISO-8601 timestamp of most recent transaction |
| `branch_code` | `TEXT` | `NULL` | Originating branch or digital channel ID |

### 2.6 `counterparties`
External individuals, merchants, correspondent banks, or internal target accounts.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `external_account_ref` | `TEXT` | `NOT NULL` | IBAN, routing/account number, or wallet address |
| `name` | `TEXT` | `NOT NULL` | Counterparty name |
| `entity_type` | `TEXT` | `NOT NULL` | `INDIVIDUAL`, `CORPORATE`, `MERCHANT`, `FINANCIAL_INSTITUTION`, `EXCHANGE` |
| `bank_name` | `TEXT` | `NULL` | Beneficiary/originating bank name |
| `bank_bic_swift` | `TEXT` | `NULL` | SWIFT/BIC identifier |
| `country_code` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 jurisdiction |
| `mcc_code` | `TEXT` | `NULL` | 4-digit Merchant Category Code |
| `is_high_risk_jurisdiction` | `INTEGER` | `NOT NULL DEFAULT 0` | FATF high-risk or offshore haven flag |
| `linked_internal_account_id` | `TEXT` | `NULL REFERENCES accounts(id)` | Populated if counterparty is an internal account |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.7 `transactions`
Canonical immutable financial transaction ledger.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `external_tx_id` | `TEXT` | `UNIQUE NOT NULL` | Core processor transaction reference |
| `account_id` | `TEXT` | `NOT NULL REFERENCES accounts(id)` | Primary internal account |
| `customer_id` | `TEXT` | `NOT NULL REFERENCES customers(id)` | Denormalized customer ID for fast indexing |
| `counterparty_id` | `TEXT` | `NULL REFERENCES counterparties(id)` | External or internal counterparty |
| `counterparty_account_id` | `TEXT` | `NULL REFERENCES accounts(id)` | Direct internal account link for internal/graph transfers |
| `tx_timestamp` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |
| `tx_type` | `TEXT` | `NOT NULL` | `CASH_DEPOSIT`, `CASH_WITHDRAWAL`, `WIRE_DOMESTIC`, `WIRE_INTERNATIONAL`, `ACH_CREDIT`, `ACH_DEBIT`, `CARD_POS`, `CARD_ECOMMERCE`, `INTERNAL_TRANSFER`, `CRYPTO_EXCHANGE` |
| `direction` | `TEXT` | `NOT NULL` | `INBOUND` (Credit) or `OUTBOUND` (Debit) |
| `amount_original` | `REAL` | `NOT NULL` | Amount in original currency |
| `currency_original` | `TEXT` | `NOT NULL DEFAULT 'USD'` | Original ISO-4217 currency |
| `fx_rate_to_usd` | `REAL` | `NOT NULL DEFAULT 1.0` | Conversion rate applied |
| `amount_usd` | `REAL` | `NOT NULL` | Normalized USD amount |
| `balance_after_usd` | `REAL` | `NOT NULL DEFAULT 0.0` | Account balance post-transaction |
| `channel` | `TEXT` | `NOT NULL` | `BRANCH`, `ATM`, `ONLINE_WEB`, `MOBILE_APP`, `API_GATEWAY`, `SWIFT_NET` |
| `origin_country` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 origin country |
| `destination_country` | `TEXT` | `NOT NULL` | ISO-3166 alpha-2 destination country |
| `ip_address` | `TEXT` | `NULL` | Client IPv4/IPv6 address |
| `device_fingerprint` | `TEXT` | `NULL` | Hardware/browser fingerprint hash |
| `geo_lat` | `REAL` | `NULL` | Latitude coordinate |
| `geo_lon` | `REAL` | `NULL` | Longitude coordinate |
| `branch_or_atm_id` | `TEXT` | `NULL` | Physical terminal identifier |
| `remittance_purpose` | `TEXT` | `NULL` | Free-text payment memo / invoice description |
| `scenario_tag` | `TEXT` | `NULL` | Ground-truth simulation tag for backtesting validation |
| `is_flagged` | `INTEGER` | `NOT NULL DEFAULT 0` | `1` if linked to one or more alerts |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.8 `typology_rules` & `rule_versions`
Stores the 25+ configurable typology rules, their JSON parameters, and version history.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | Rule code (e.g., `AML-STR-001`) |
| `name` | `TEXT` | `NOT NULL` | Rule title |
| `family` | `TEXT` | `NOT NULL` | `STRUCTURING`, `LAYERING`, `MULE_NETWORK`, `GEOGRAPHIC`, `BEHAVIORAL_FRAUD` |
| `severity` | `TEXT` | `NOT NULL` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `description` | `TEXT` | `NOT NULL` | Detailed compliance specification |
| `parameters_json` | `TEXT` | `NOT NULL` | JSON object of active thresholds |
| `is_enabled` | `INTEGER` | `NOT NULL DEFAULT 1` | `1` = active in production, `0` = disabled |
| `version` | `INTEGER` | `NOT NULL DEFAULT 1` | Monotonically increasing version number |
| `regulatory_citation` | `TEXT` | `NOT NULL` | FinCEN / FATF / BSA reference |
| `updated_by` | `TEXT` | `NULL REFERENCES users(id)` | Last engineer who updated the rule |
| `updated_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |

### 2.9 `alerts` & `alert_transactions`
Stores generated alerts and the specific transactions that triggered them.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `TEXT` | `PRIMARY KEY` | UUID v4 |
| `alert_ref` | `TEXT` | `UNIQUE NOT NULL` | Human-readable ID (e.g., `ALT-2026-000104`) |
| `customer_id` | `TEXT` | `NOT NULL REFERENCES customers(id)` | Subject customer |
| `account_id` | `TEXT` | `NOT NULL REFERENCES accounts(id)` | Subject account |
| `rule_id` | `TEXT` | `NOT NULL REFERENCES typology_rules(id)` | Triggered typology rule |
| `rule_version` | `INTEGER` | `NOT NULL` | Version of rule at trigger time |
| `severity` | `TEXT` | `NOT NULL` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `risk_score` | `REAL` | `NOT NULL` | 0.0 to 100.0 composite alert priority score |
| `status` | `TEXT` | `NOT NULL DEFAULT 'NEW'` | `NEW`, `IN_TRIAGE`, `ESCALATED_TO_CASE`, `DISMISSED_FALSE_POSITIVE` |
| `trigger_narrative` | `TEXT` | `NOT NULL` | Explainable summary of threshold breach |
| `evidence_metrics_json` | `TEXT` | `NOT NULL` | Structured JSON metrics (window totals, ratios, z-scores) |
| `assigned_to` | `TEXT` | `NULL REFERENCES users(id)` | Assigned L1/L2 analyst |
| `case_id` | `TEXT` | `NULL REFERENCES cases(id)` | Linked investigation case if escalated |
| `disposition_reason` | `TEXT` | `NULL` | Reason code & justification when dismissed |
| `sla_due_at` | `TEXT` | `NOT NULL` | SLA target timestamp |
| `created_at` | `TEXT` | `NOT NULL` | ISO-8601 UTC timestamp |
| `resolved_at` | `TEXT` | `NULL` | ISO-8601 UTC timestamp |

### 2.10 `cases`, `case_notes`, `case_evidence` & `sar_reports`
Manages L1/L2/QA investigations, evidence lockers, and FinCEN SAR filings.
- **`cases`**: Tracks `case_number`, `primary_customer_id`, `title`, `status` (`OPEN`, `IN_REVIEW_L1`, `ESCALATED_L2`, `PENDING_QA_APPROVAL`, `SAR_APPROVED`, `SAR_FILED`, `CLOSED_FALSE_POSITIVE`, `CLOSED_NO_SAR`), `priority`, `investigator_id`, `qa_reviewer_id`, `total_suspicious_amount_usd`, `typology_tags_json`, `disposition_summary`, `opened_at`, `qa_submitted_at`, `closed_at`.
- **`sar_reports`**: Tracks `sar_ref`, `case_id`, `subject_customer_id`, `filing_type` (`INITIAL`, `CONTINUING_ACTIVITY`, `JOINT`), `activity_start_date`, `activity_end_date`, `total_suspicious_amount_usd`, `narrative_who`, `narrative_what`, `narrative_when`, `narrative_where`, `narrative_why_how`, `full_narrative_text`, `Prepared_by`, `approved_by`, `filing_status` (`DRAFT`, `READY_FOR_QA`, `APPROVED`, `FILED_WITH_FINCEN`), `fincen_bsa_id`, `content_sha256`.

### 2.11 `simulation_runs`
Stores Shadow-Mode Rule Backtesting jobs, candidate parameters, confusion matrices (`tp`, `fp`, `tn`, `fn`), `precision_score`, `recall_score`, `f1_score`, `baseline_alert_count`, `candidate_alert_count`, and `sample_diff_json`.

### 2.12 `watchlist_entries` & `sanctions_hits`
Stores sanctions/PEP watchlist records (`OFAC_SDN`, `UN_CONSOLIDATED`, `EU_SANCTIONS`, `PEP_GLOBAL`, `ADVERSE_MEDIA`) and fuzzy screening hits with `similarity_score`, `matched_algorithm`, and analyst disposition.

### 2.13 `audit_logs`
Cryptographically hash-chained immutable audit log (`sequence_id`, `timestamp`, `actor_user_id`, `actor_role`, `action`, `entity_type`, `entity_id`, `details_json`, `previous_hash`, `entry_hash`).
