-- Migration 001: SentinelGraph Core Relational & Graph Schema
-- Enforces foreign key integrity and creates indexes for high-throughput typology and graph queries.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('L1_ANALYST', 'L2_INVESTIGATOR', 'QA_COMPLIANCE_OFFICER', 'RISK_ENGINEER', 'SYSTEM_ADMIN')),
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    last_login_at TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    external_ref TEXT UNIQUE NOT NULL,
    customer_type TEXT NOT NULL CHECK (customer_type IN ('INDIVIDUAL', 'BUSINESS')),
    legal_name TEXT NOT NULL,
    date_of_birth_or_inc TEXT NOT NULL,
    nationality_or_reg_country TEXT NOT NULL,
    residence_country TEXT NOT NULL,
    occupation_or_industry TEXT NOT NULL,
    naics_code TEXT NULL,
    tax_id_hash TEXT NOT NULL,
    email TEXT NULL,
    phone_number TEXT NULL,
    physical_address TEXT NULL,
    expected_monthly_volume_usd REAL NOT NULL DEFAULT 5000.0,
    pep_flag INTEGER NOT NULL DEFAULT 0,
    adverse_media_flag INTEGER NOT NULL DEFAULT 0,
    sanctions_status TEXT NOT NULL DEFAULT 'CLEAR' CHECK (sanctions_status IN ('CLEAR', 'POTENTIAL_MATCH', 'CONFIRMED_MATCH')),
    kyc_verification_level TEXT NOT NULL DEFAULT 'STANDARD' CHECK (kyc_verification_level IN ('SIMPLIFIED', 'STANDARD', 'ENHANCED_DUE_DILIGENCE')),
    composite_risk_score REAL NOT NULL DEFAULT 15.0,
    risk_band TEXT NOT NULL DEFAULT 'LOW' CHECK (risk_band IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_factors_json TEXT NOT NULL DEFAULT '{}',
    onboarding_date TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_customers_risk_band ON customers(risk_band);
CREATE INDEX IF NOT EXISTS idx_customers_tax_id_hash ON customers(tax_id_hash);
CREATE INDEX IF NOT EXISTS idx_customers_residence ON customers(residence_country);

CREATE TABLE IF NOT EXISTS beneficial_owners (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    linked_individual_customer_id TEXT NULL REFERENCES customers(id) ON DELETE SET NULL,
    full_name TEXT NOT NULL,
    nationality TEXT NOT NULL,
    residence_country TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    ownership_percentage REAL NOT NULL CHECK (ownership_percentage >= 0.0 AND ownership_percentage <= 100.0),
    is_control_person INTEGER NOT NULL DEFAULT 0,
    is_pep INTEGER NOT NULL DEFAULT 0,
    tax_id_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ubo_customer_id ON beneficial_owners(customer_id);
CREATE INDEX IF NOT EXISTS idx_ubo_tax_id_hash ON beneficial_owners(tax_id_hash);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    account_number TEXT UNIQUE NOT NULL,
    account_type TEXT NOT NULL CHECK (account_type IN ('CHECKING', 'SAVINGS', 'COMMERCIAL_TREASURY', 'MERCHANT_SETTLEMENT', 'CRYPTO_WALLET')),
    currency TEXT NOT NULL DEFAULT 'USD',
    current_balance_usd REAL NOT NULL DEFAULT 0.0,
    average_30d_balance_usd REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DORMANT', 'RESTRICTED', 'FROZEN', 'CLOSED')),
    opened_at TEXT NOT NULL,
    last_activity_at TEXT NULL,
    branch_code TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_customer_id ON accounts(customer_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

CREATE TABLE IF NOT EXISTS counterparties (
    id TEXT PRIMARY KEY,
    external_account_ref TEXT NOT NULL,
    name TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('INDIVIDUAL', 'CORPORATE', 'MERCHANT', 'FINANCIAL_INSTITUTION', 'EXCHANGE')),
    bank_name TEXT NULL,
    bank_bic_swift TEXT NULL,
    country_code TEXT NOT NULL,
    mcc_code TEXT NULL,
    is_high_risk_jurisdiction INTEGER NOT NULL DEFAULT 0,
    linked_internal_account_id TEXT NULL REFERENCES accounts(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_counterparties_country ON counterparties(country_code);
CREATE INDEX IF NOT EXISTS idx_counterparties_internal_acct ON counterparties(linked_internal_account_id);

CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    external_tx_id TEXT UNIQUE NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    counterparty_id TEXT NULL REFERENCES counterparties(id) ON DELETE SET NULL,
    counterparty_account_id TEXT NULL REFERENCES accounts(id) ON DELETE SET NULL,
    tx_timestamp TEXT NOT NULL,
    tx_type TEXT NOT NULL CHECK (tx_type IN ('CASH_DEPOSIT', 'CASH_WITHDRAWAL', 'WIRE_DOMESTIC', 'WIRE_INTERNATIONAL', 'ACH_CREDIT', 'ACH_DEBIT', 'CARD_POS', 'CARD_ECOMMERCE', 'INTERNAL_TRANSFER', 'CRYPTO_EXCHANGE')),
    direction TEXT NOT NULL CHECK (direction IN ('INBOUND', 'OUTBOUND')),
    amount_original REAL NOT NULL CHECK (amount_original > 0),
    currency_original TEXT NOT NULL DEFAULT 'USD',
    fx_rate_to_usd REAL NOT NULL DEFAULT 1.0,
    amount_usd REAL NOT NULL CHECK (amount_usd > 0),
    balance_after_usd REAL NOT NULL DEFAULT 0.0,
    channel TEXT NOT NULL CHECK (channel IN ('BRANCH', 'ATM', 'ONLINE_WEB', 'MOBILE_APP', 'API_GATEWAY', 'SWIFT_NET')),
    origin_country TEXT NOT NULL,
    destination_country TEXT NOT NULL,
    ip_address TEXT NULL,
    device_fingerprint TEXT NULL,
    geo_lat REAL NULL,
    geo_lon REAL NULL,
    mcc_code TEXT NULL,
    branch_or_atm_id TEXT NULL,
    remittance_purpose TEXT NULL,
    scenario_tag TEXT NULL,
    is_flagged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tx_account_time ON transactions(account_id, tx_timestamp);
CREATE INDEX IF NOT EXISTS idx_tx_customer_time ON transactions(customer_id, tx_timestamp);
CREATE INDEX IF NOT EXISTS idx_tx_type_amount ON transactions(tx_type, amount_usd);
CREATE INDEX IF NOT EXISTS idx_tx_counterparty_acct ON transactions(counterparty_account_id);
CREATE INDEX IF NOT EXISTS idx_tx_device ON transactions(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_tx_ip ON transactions(ip_address);

CREATE TABLE IF NOT EXISTS typology_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    family TEXT NOT NULL CHECK (family IN ('STRUCTURING', 'LAYERING', 'MULE_NETWORK', 'GEOGRAPHIC', 'BEHAVIORAL_FRAUD')),
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    description TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    regulatory_citation TEXT NOT NULL,
    updated_by TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_versions (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES typology_rules(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    parameters_json TEXT NOT NULL,
    is_enabled INTEGER NOT NULL,
    change_reason TEXT NOT NULL,
    changed_by TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT UNIQUE NOT NULL,
    primary_customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_REVIEW_L1', 'ESCALATED_L2', 'PENDING_QA_APPROVAL', 'SAR_APPROVED', 'SAR_FILED', 'CLOSED_FALSE_POSITIVE', 'CLOSED_NO_SAR')),
    priority TEXT NOT NULL DEFAULT 'HIGH' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    investigator_id TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    qa_reviewer_id TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    total_suspicious_amount_usd REAL NOT NULL DEFAULT 0.0,
    typology_tags_json TEXT NOT NULL DEFAULT '[]',
    disposition_summary TEXT NULL,
    qa_decision_notes TEXT NULL,
    opened_at TEXT NOT NULL,
    qa_submitted_at TEXT NULL,
    closed_at TEXT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_customer ON cases(primary_customer_id);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    alert_ref TEXT UNIQUE NOT NULL,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL REFERENCES typology_rules(id) ON DELETE CASCADE,
    rule_version INTEGER NOT NULL DEFAULT 1,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'IN_TRIAGE', 'ESCALATED_TO_CASE', 'DISMISSED_FALSE_POSITIVE')),
    trigger_narrative TEXT NOT NULL,
    evidence_metrics_json TEXT NOT NULL DEFAULT '{}',
    assigned_to TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    case_id TEXT NULL REFERENCES cases(id) ON DELETE SET NULL,
    disposition_reason TEXT NULL,
    sla_due_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_at TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_customer ON alerts(customer_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_case ON alerts(case_id);

CREATE TABLE IF NOT EXISTS alert_transactions (
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    transaction_id TEXT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    contribution_weight REAL NOT NULL DEFAULT 1.0,
    PRIMARY KEY (alert_id, transaction_id)
);

CREATE TABLE IF NOT EXISTS case_notes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    author_role TEXT NOT NULL,
    note_type TEXT NOT NULL DEFAULT 'INVESTIGATION_NOTE' CHECK (note_type IN ('INVESTIGATION_NOTE', 'EVIDENCE_ATTACHMENT', 'ESCALATION_MEMO', 'QA_REVIEW_COMMENT', 'SYSTEM_EVENT')),
    content TEXT NOT NULL,
    attachment_hash TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sar_reports (
    id TEXT PRIMARY KEY,
    sar_ref TEXT UNIQUE NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    subject_customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    filing_type TEXT NOT NULL DEFAULT 'INITIAL' CHECK (filing_type IN ('INITIAL', 'CONTINUING_ACTIVITY', 'JOINT')),
    activity_start_date TEXT NOT NULL,
    activity_end_date TEXT NOT NULL,
    total_suspicious_amount_usd REAL NOT NULL,
    typology_codes_json TEXT NOT NULL DEFAULT '[]',
    narrative_who TEXT NOT NULL,
    narrative_what TEXT NOT NULL,
    narrative_when TEXT NOT NULL,
    narrative_where TEXT NOT NULL,
    narrative_why_how TEXT NOT NULL,
    full_narrative_text TEXT NOT NULL,
    prepared_by TEXT NOT NULL REFERENCES users(id),
    approved_by TEXT NULL REFERENCES users(id),
    filing_status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (filing_status IN ('DRAFT', 'READY_FOR_QA', 'APPROVED', 'FILED_WITH_FINCEN')),
    fincen_bsa_id TEXT NULL,
    content_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    filed_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS ctr_reports (
    id TEXT PRIMARY KEY,
    ctr_ref TEXT UNIQUE NOT NULL,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    aggregation_date TEXT NOT NULL,
    total_cash_in_usd REAL NOT NULL DEFAULT 0.0,
    total_cash_out_usd REAL NOT NULL DEFAULT 0.0,
    transaction_ids_json TEXT NOT NULL DEFAULT '[]',
    filing_status TEXT NOT NULL DEFAULT 'GENERATED' CHECK (filing_status IN ('GENERATED', 'FILED_WITH_FINCEN')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulation_runs (
    id TEXT PRIMARY KEY,
    run_ref TEXT UNIQUE NOT NULL,
    rule_id TEXT NOT NULL REFERENCES typology_rules(id) ON DELETE CASCADE,
    created_by TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    baseline_parameters_json TEXT NOT NULL,
    candidate_parameters_json TEXT NOT NULL,
    transactions_evaluated INTEGER NOT NULL,
    baseline_alert_count INTEGER NOT NULL,
    candidate_alert_count INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    false_positives INTEGER NOT NULL,
    true_negatives INTEGER NOT NULL,
    false_negatives INTEGER NOT NULL,
    precision_score REAL NOT NULL,
    recall_score REAL NOT NULL,
    f1_score REAL NOT NULL,
    alert_volume_delta_pct REAL NOT NULL,
    estimated_hours_saved REAL NOT NULL,
    sample_diff_json TEXT NOT NULL DEFAULT '{}',
    notes TEXT NULL,
    executed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist_entries (
    id TEXT PRIMARY KEY,
    list_source TEXT NOT NULL CHECK (list_source IN ('OFAC_SDN', 'UN_CONSOLIDATED', 'EU_SANCTIONS', 'PEP_GLOBAL', 'ADVERSE_MEDIA')),
    entity_type TEXT NOT NULL CHECK (entity_type IN ('INDIVIDUAL', 'ENTITY', 'VESSEL')),
    primary_name TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    date_of_birth TEXT NULL,
    nationality_country TEXT NOT NULL,
    program_Or_category TEXT NOT NULL,
    risk_weight REAL NOT NULL DEFAULT 95.0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sanctions_hits (
    id TEXT PRIMARY KEY,
    customer_id TEXT NULL REFERENCES customers(id) ON DELETE CASCADE,
    screened_name TEXT NOT NULL,
    watchlist_entry_id TEXT NOT NULL REFERENCES watchlist_entries(id) ON DELETE CASCADE,
    matched_name TEXT NOT NULL,
    similarity_score REAL NOT NULL,
    phonetic_match INTEGER NOT NULL DEFAULT 0,
    dob_match INTEGER NOT NULL DEFAULT 0,
    country_match INTEGER NOT NULL DEFAULT 0,
    algorithm_breakdown_json TEXT NOT NULL DEFAULT '{}',
    disposition TEXT NOT NULL DEFAULT 'PENDING_REVIEW' CHECK (disposition IN ('PENDING_REVIEW', 'TRUE_MATCH', 'FALSE_POSITIVE', 'POTENTIAL_MATCH_ESCALATED')),
    reviewed_by TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    review_notes TEXT NULL,
    created_at TEXT NOT NULL,
    reviewed_at TEXT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT UNIQUE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_user_id);
