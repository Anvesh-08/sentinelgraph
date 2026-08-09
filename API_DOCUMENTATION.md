# SentinelGraph — REST API Documentation (`API_DOCUMENTATION.md`)

**Base URL:** `http://127.0.0.1:8000/api/v1`  
**Content-Type:** `application/json`  
**Authentication:** Bearer Token (`Authorization: Bearer <signed_token>`)  

---

## 1. Authentication & Authorization (`RBAC`)

### 1.1 `POST /api/v1/auth/login`
Authenticates a user and returns a signed HMAC-SHA256 bearer token.
- **Request Body:**
  ```json
  {
    "username": "l2_investigator",
    "password": "Investigator#2026!Secure"
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "access_token": "eyJ1c2VyX2lkIjogIi...",
    "token_type": "bearer",
    "expires_in": 28800,
    "user": {
      "id": "usr-002",
      "username": "l2_investigator",
      "full_name": "Priya Nair",
      "role": "L2_INVESTIGATOR"
    }
  }
  ```

### 1.2 Role Permission Matrix
| Endpoint Family | `L1_ANALYST` | `L2_INVESTIGATOR` | `QA_COMPLIANCE_OFFICER` | `RISK_ENGINEER` | `SYSTEM_ADMIN` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| View Dashboard, Customers & Alerts | Yes | Yes | Yes | Yes | Yes |
| Triage Alert / Dismiss False Positive | Yes | Yes | Yes | No | Yes |
| Escalate Alert to Case / Deep Investigation | Yes | Yes | Yes | No | Yes |
| Draft SAR & Submit Case for QA | No | Yes | Yes | No | Yes |
| Approve Case & File FinCEN SAR (4-Eyes) | No | No | Yes | No | Yes |
| Run RuleForge Shadow Backtests & Tune Rules | No | Read-Only | Read-Only | Yes | Yes |
| Verify Audit Hash Chain Integrity | No | No | Yes | No | Yes |

---

## 2. Executive & Operational Analytics Endpoints

### 2.1 `GET /api/v1/analytics/dashboard`
Returns comprehensive operational KPIs:
- Alert queue counts by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and status.
- SLA compliance percentage and overdue alert counts.
- Case pipeline breakdown across L1, L2, QA, and filed SARs.
- Top triggered typology rules and total suspicious USD volume under investigation.
- High-risk customer distribution across risk bands.

---

## 3. Customer KYC, KYB & Risk Scoring Endpoints

- **`GET /api/v1/customers`**: Paginated list of customers with filtering by `risk_band`, `customer_type`, `pep_flag`, `country`, and search query.
- **`GET /api/v1/customers/{customer_id}`**: Returns complete KYC/KYB profile, accounts, beneficial owners, 90-day transaction velocity statistics, active alerts, and latest composite risk breakdown.
- **`POST /api/v1/customers/{customer_id}/recalculate-risk`**: Executes the 6-factor composite risk model and stores a new risk assessment snapshot.

---

## 4. Transaction Ingestion & Evaluation Endpoints

- **`GET /api/v1/transactions`**: Filterable ledger query (`account_id`, `customer_id`, `tx_type`, `direction`, `min_amount`, `max_amount`, `is_flagged`).
- **`POST /api/v1/transactions/ingest`**: Ingests a single or batch transaction payload, normalizes currency, evaluates all enabled typology rules in real time, and returns any newly generated alerts.
- **`POST /api/v1/typologies/evaluate-all`**: Runs batch window evaluation across the transaction ledger for all active typology rules.

---

## 5. Typology Rules & RuleForge Shadow-Mode Backtesting

- **`GET /api/v1/rules`**: Lists all 25+ AML and fraud typology rules, their active threshold parameters, regulatory citations, and historical trigger counts.
- **`PATCH /api/v1/rules/{rule_id}`**: Updates rule parameters or enabled state, increments rule version, and records a cryptographic audit entry.
- **`POST /api/v1/simulations/backtest`**: Runs a shadow-mode backtest for a specified `rule_id` and `candidate_parameters` dictionary against labeled historical transactions, returning confusion matrix metrics (`precision`, `recall`, `f1_score`, `fp_reduction_pct`, `added_alerts`, `dropped_alerts`).
- **`GET /api/v1/simulations`**: Lists historical backtest simulation runs.

---

## 6. Multi-Hop Graph Investigation Endpoints

- **`GET /api/v1/graph/ego/{entity_type}/{entity_id}?hops=3`**: Extracts the K-hop ego subgraph around a customer or account, returning nodes, monetary flow edges, shared-attribute edges (devices, IPs, addresses, UBOs), PageRank centrality scores, and detected rings/cycles.
- **`GET /api/v1/graph/paths?source_account_id=...&target_account_id=...&max_hops=5`**: Computes all temporal fund flow paths between two accounts.
- **`GET /api/v1/graph/rings`**: Runs global Tarjan SCC, temporal cycle detection, fan-in/fan-out hub analysis, and shared-attribute cluster detection to surface high-risk criminal networks.

---

## 7. Alert Triage, Case Management & SAR Filing Endpoints

- **`GET /api/v1/alerts`**: Filterable queue of alerts (`severity`, `status`, `rule_id`, `assigned_to`).
- **`POST /api/v1/alerts/{alert_id}/triage`**: Assigns an alert, dismisses it as `DISMISSED_FALSE_POSITIVE` with mandatory justification, or escalates it into a new or existing `Case`.
- **`GET /api/v1/cases`**: Lists investigation cases with status, investigator, QA reviewer, and suspicious dollar totals.
- **`GET /api/v1/cases/{case_id}`**: Full case dossier including linked alerts, transactions, investigator notes, evidence locker items, and draft/filed SAR reports.
- **`POST /api/v1/cases/{case_id}/notes`**: Appends an immutable investigator note to the case timeline.
- **`POST /api/v1/cases/{case_id}/transition`**: Transitions case state (`OPEN` -> `IN_REVIEW_L1` -> `ESCALATED_L2` -> `PENDING_QA_APPROVAL` -> `SAR_APPROVED` -> `SAR_FILED`), strictly enforcing Four-Eyes separation of duties on QA approval.
- **`POST /api/v1/cases/{case_id}/generate-sar`**: Invokes the structured FinCEN 5-W SAR narrative builder (`WHO`, `WHAT`, `WHEN`, `WHERE`, `WHY_HOW`) and persists a verifiable SAR report with a SHA-256 content digest.

---

## 8. Sanctions Screening & Cryptographic Audit Verification

- **`POST /api/v1/sanctions/screen`**: Screens a name, DOB, and country against the watchlist using Jaro-Winkler, Levenshtein, Token-Set, and Soundex phonetic matching.
- **`GET /api/v1/audit/logs`**: Paginated view of the hash-chained audit ledger.
- **`GET /api/v1/audit/verify`**: Recomputes every HMAC-SHA256 link in the audit chain from genesis (`GENESIS_0000...`) to the latest record and confirms zero tampering.
