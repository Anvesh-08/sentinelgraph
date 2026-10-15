"""
Complete FastAPI REST API router for SentinelGraph (`/api/v1/*`).
Provides RBAC-protected endpoints for Authentication, Executive Analytics,
Customers & KYC Risk, Transactions & Real-Time Evaluation, Typology Rules,
RuleForge Shadow Backtesting, Multi-Hop Graph Forensics, Alert Triage,
Four-Eyes Case Management, FinCEN SAR Generation, Sanctions Screening,
and Cryptographic Audit Chain Verification.
"""
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, Query

from backend.app.audit.service import AuditService
from backend.app.cases.service import CaseManagementService
from backend.app.core.config import settings
from backend.app.core.exceptions import AuthenticationError
from backend.app.core.security import (
    Permission,
    assert_permission,
    create_access_token,
    decode_and_verify_token,
    verify_password,
)
from backend.app.db.connection import DatabaseManager, default_db
from backend.app.graph.engine import GraphForensicsEngine
from backend.app.reporting.sar_generator import FinCENSarGenerator
from backend.app.repositories.core_repositories import (
    AccountRepository,
    CustomerRepository,
    RuleRepository,
    TransactionRepository,
    UserRepository,
)
from backend.app.risk.engine import CompositeRiskEngine
from backend.app.sanctions.screener import SanctionsScreeningService
from backend.app.schemas.api_schemas import (
    AlertTriageRequest,
    CaseNoteCreateRequest,
    CaseStateTransitionRequest,
    LoginRequest,
    RuleUpdateRequest,
    SARGenerationRequest,
    SanctionsHitDispositionRequest,
    SanctionsScreenRequest,
    ShadowBacktestRequest,
    TransactionIngestRequest,
)
from backend.app.simulation.engine import RuleSimulationEngine
from backend.app.typologies.engine import TypologyEngine


router = APIRouter(prefix="/api/v1")


def get_db() -> DatabaseManager:
    return default_db


def get_current_user(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthenticationError("Missing or invalid Authorization Bearer header.")
    token = authorization.split(" ", 1)[1].strip()
    claims = decode_and_verify_token(token)
    return {
        "id": claims["sub"],
        "username": claims["username"],
        "role": claims["role"],
        "full_name": claims.get("full_name", ""),
    }


# ------------------------------------------------------------------------------
# 1. Authentication & Operator Profiles
# ------------------------------------------------------------------------------

@router.post("/auth/login")
def login(payload: LoginRequest, db: DatabaseManager = Depends(get_db)) -> Dict[str, Any]:
    user_repo = UserRepository(db)
    user = user_repo.get_by_username(payload.username)
    if not user or not int(user.get("is_active", 1)):
        raise AuthenticationError("Invalid username or password.")
    if not verify_password(payload.password, user["password_hash"], user["password_salt"]):
        raise AuthenticationError("Invalid username or password.")

    user_repo.update_last_login(user["id"])
    token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role"],
        full_name=user["full_name"],
    )
    AuditService(db).record_event(
        actor_user_id=user["id"],
        actor_role=user["role"],
        action="USER_LOGIN",
        entity_type="User",
        entity_id=user["id"],
        details={"username": user["username"]},
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.token_ttl_seconds,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        },
    }


@router.get("/auth/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return current_user


@router.get("/users")
def list_operators(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    return {"users": UserRepository(db).list_users()}


# ------------------------------------------------------------------------------
# 2. Executive & Operational KPI Dashboard
# ------------------------------------------------------------------------------

@router.get("/analytics/dashboard")
def get_dashboard_kpis(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    with db.connection() as conn:
        alert_sev = {
            r["severity"]: r["cnt"]
            for r in conn.execute("SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity").fetchall()
        }
        alert_status = {
            r["status"]: r["cnt"]
            for r in conn.execute("SELECT status, COUNT(*) AS cnt FROM alerts GROUP BY status").fetchall()
        }
        case_status = {
            r["status"]: r["cnt"]
            for r in conn.execute("SELECT status, COUNT(*) AS cnt FROM cases GROUP BY status").fetchall()
        }
        risk_bands = {
            r["risk_band"]: r["cnt"]
            for r in conn.execute("SELECT risk_band, COUNT(*) AS cnt FROM customers GROUP BY risk_band").fetchall()
        }
        top_rules = [
            dict(r)
            for r in conn.execute(
                """
                SELECT a.rule_id, r.name AS rule_name, r.family, COUNT(*) AS alert_count,
                       ROUND(AVG(a.risk_score), 1) AS avg_score
                FROM alerts a
                JOIN typology_rules r ON r.id = a.rule_id
                GROUP BY a.rule_id
                ORDER BY alert_count DESC, avg_score DESC
                LIMIT 10
                """
            ).fetchall()
        ]
        totals = dict(
            conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM customers) AS total_customers,
                    (SELECT COUNT(*) FROM accounts) AS total_accounts,
                    (SELECT COUNT(*) FROM transactions) AS total_transactions,
                    (SELECT COALESCE(SUM(amount_usd), 0.0) FROM transactions) AS total_tx_volume_usd,
                    (SELECT COUNT(*) FROM alerts) AS total_alerts,
                    (SELECT COUNT(*) FROM cases) AS total_cases,
                    (SELECT COALESCE(SUM(total_suspicious_amount_usd), 0.0) FROM cases) AS total_suspicious_case_usd,
                    (SELECT COUNT(*) FROM sar_reports) AS total_sars,
                    (SELECT COUNT(*) FROM ctr_reports) AS total_ctrs,
                    (SELECT COUNT(*) FROM sanctions_hits) AS total_sanctions_hits
                """
            ).fetchone()
        )

    audit_integrity = AuditService(db).verify_chain_integrity(raise_on_error=False)
    return {
        "totals": totals,
        "alerts_by_severity": alert_sev,
        "alerts_by_status": alert_status,
        "cases_by_status": case_status,
        "customers_by_risk_band": risk_bands,
        "top_triggered_rules": top_rules,
        "audit_ledger_integrity": {
            "is_valid": audit_integrity["is_valid"],
            "total_records_verified": audit_integrity["total_records_verified"],
            "latest_tip_hash": audit_integrity["latest_tip_hash"][:16] + "...",
        },
    }


# ------------------------------------------------------------------------------
# 3. Customers, KYC/KYB Profiles & Composite Risk Scoring
# ------------------------------------------------------------------------------

@router.get("/customers")
def list_customers(
    risk_band: Optional[str] = Query(default=None),
    customer_type: Optional[str] = Query(default=None),
    pep_flag: Optional[int] = Query(default=None),
    search: Optional[str] = Query(default=None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_CUSTOMERS)
    repo = CustomerRepository(db)
    items = repo.list_customers(
        risk_band=risk_band,
        customer_type=customer_type,
        pep_flag=pep_flag,
        search=search,
    )
    return {"count": len(items), "customers": items}


@router.get("/customers/{customer_id}")
def get_customer_dossier(
    customer_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_CUSTOMERS)
    cust_repo = CustomerRepository(db)
    customer = cust_repo.get_by_id(customer_id)
    ubos = cust_repo.get_beneficial_owners(customer_id)
    accounts = AccountRepository(db).list_by_customer(customer_id)
    txs = TransactionRepository(db).list_transactions(customer_id=customer_id, limit=200)
    alerts = CaseManagementService(db).list_alerts(customer_id=customer_id)
    return {
        "customer": customer,
        "beneficial_owners": ubos,
        "accounts": accounts,
        "recent_transactions": txs,
        "alerts": alerts,
    }


@router.post("/customers/{customer_id}/recalculate-risk")
def recalculate_customer_risk(
    customer_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.RECALCULATE_RISK)
    breakdown = CompositeRiskEngine(db).evaluate_customer(customer_id, persist=True)
    AuditService(db).record_event(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        action="CUSTOMER_RISK_RECALCULATED",
        entity_type="Customer",
        entity_id=customer_id,
        details={"score": breakdown["composite_risk_score"], "band": breakdown["risk_band"]},
    )
    return breakdown


# ------------------------------------------------------------------------------
# 4. Transactions & Real-Time Typology Ingestion
# ------------------------------------------------------------------------------

@router.get("/transactions")
def list_transactions(
    account_id: Optional[str] = Query(default=None),
    customer_id: Optional[str] = Query(default=None),
    tx_type: Optional[str] = Query(default=None),
    direction: Optional[str] = Query(default=None),
    min_amount_usd: Optional[float] = Query(default=None),
    is_flagged: Optional[int] = Query(default=None),
    limit: int = Query(default=200, le=1000),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_CUSTOMERS)
    txs = TransactionRepository(db).list_transactions(
        account_id=account_id,
        customer_id=customer_id,
        tx_type=tx_type,
        direction=direction,
        min_amount_usd=min_amount_usd,
        is_flagged=is_flagged,
        limit=limit,
    )
    return {"count": len(txs), "transactions": txs}


@router.post("/transactions/ingest")
def ingest_transaction(
    payload: TransactionIngestRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.INGEST_TRANSACTIONS)
    tx_repo = TransactionRepository(db)
    inserted = tx_repo.insert_transaction(payload.dict())
    eval_result = None
    if payload.evaluate_rules:
        eval_result = TypologyEngine(db).evaluate_all_rules(persist_alerts=True)

    AuditService(db).record_event(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        action="TRANSACTION_INGESTED",
        entity_type="Transaction",
        entity_id=inserted["id"],
        details={"amount_usd": inserted["amount_usd"], "tx_type": inserted["tx_type"]},
    )
    return {"transaction": inserted, "evaluation_summary": eval_result}


# ------------------------------------------------------------------------------
# 5. Typology Rules & RuleForge Shadow-Mode Backtesting
# ------------------------------------------------------------------------------

@router.get("/rules")
def list_typology_rules(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    rules = RuleRepository(db).list_rules(enabled_only=False)
    return {"count": len(rules), "rules": rules}


@router.patch("/rules/{rule_id}")
def update_typology_rule(
    rule_id: str,
    payload: RuleUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.TUNE_RULES_AND_SIMULATE)
    updated = RuleRepository(db).update_rule(
        rule_id=rule_id,
        parameters=payload.parameters,
        is_enabled=payload.is_enabled,
        change_reason=payload.change_reason,
        actor_user_id=current_user["id"],
    )
    AuditService(db).record_event(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        action="TYPOLOGY_RULE_UPDATED",
        entity_type="TypologyRule",
        entity_id=rule_id,
        details={"version": updated["version"], "reason": payload.change_reason},
    )
    return updated


@router.post("/simulations/backtest")
def run_shadow_backtest(
    payload: ShadowBacktestRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.TUNE_RULES_AND_SIMULATE)
    result = RuleSimulationEngine(db).run_shadow_backtest(
        rule_id=payload.rule_id,
        candidate_parameters=payload.candidate_parameters,
        actor_user_id=current_user["id"],
        notes=payload.notes,
    )
    AuditService(db).record_event(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        action="SHADOW_BACKTEST_EXECUTED",
        entity_type="SimulationRun",
        entity_id=result["id"],
        details={"rule_id": payload.rule_id, "f1_score": result["f1_score"]},
    )
    return result


@router.get("/simulations")
def list_simulations(
    rule_id: Optional[str] = Query(default=None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    runs = RuleSimulationEngine(db).list_simulation_runs(rule_id=rule_id)
    return {"count": len(runs), "simulations": runs}


# ------------------------------------------------------------------------------
# 6. Multi-Hop Graph Forensics & Link Analysis
# ------------------------------------------------------------------------------

@router.get("/graph/ego/{center_id}")
def get_ego_graph(
    center_id: str,
    hops: int = Query(default=3, ge=1, le=6),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    return GraphForensicsEngine(db).get_ego_network(center_id=center_id, hops=hops)


@router.get("/graph/paths")
def get_temporal_paths(
    source_account_id: str = Query(...),
    target_account_id: str = Query(...),
    max_hops: int = Query(default=5, ge=1, le=6),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    paths = GraphForensicsEngine(db).find_temporal_flow_paths(
        source_account_id=source_account_id,
        target_account_id=target_account_id,
        max_hops=max_hops,
    )
    return {"count": len(paths), "paths": paths}


@router.get("/graph/rings")
def get_criminal_rings(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    return GraphForensicsEngine(db).detect_criminal_network_rings()


# ------------------------------------------------------------------------------
# 7. Alerts, Four-Eyes Cases & FinCEN SAR/CTR Reporting
# ------------------------------------------------------------------------------

@router.get("/alerts")
def list_alerts(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    customer_id: Optional[str] = Query(default=None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    alerts = CaseManagementService(db).list_alerts(
        status=status, severity=severity, rule_id=rule_id, customer_id=customer_id
    )
    return {"count": len(alerts), "alerts": alerts}


@router.get("/alerts/{alert_id}")
def get_alert_detail(
    alert_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    return CaseManagementService(db).get_alert(alert_id)


@router.post("/alerts/{alert_id}/triage")
def triage_alert(
    alert_id: str,
    payload: AlertTriageRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.TRIAGE_ALERT)
    return CaseManagementService(db).triage_alert(
        alert_id=alert_id,
        action=payload.action,
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        assigned_to_user_id=payload.assigned_to_user_id,
        disposition_reason=payload.disposition_reason,
        case_title=payload.case_title,
        case_priority=payload.case_priority,
        existing_case_id=payload.existing_case_id,
    )


@router.get("/cases")
def list_cases(
    status: Optional[str] = Query(default=None),
    priority: Optional[str] = Query(default=None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    cases = CaseManagementService(db).list_cases(status=status, priority=priority)
    return {"count": len(cases), "cases": cases}


@router.get("/cases/{case_id}")
def get_case_detail(
    case_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    return CaseManagementService(db).get_case(case_id)


@router.post("/cases/{case_id}/notes")
def add_case_note(
    case_id: str,
    payload: CaseNoteCreateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.MANAGE_CASE_L1_L2)
    return CaseManagementService(db).add_case_note(
        case_id=case_id,
        author_user_id=current_user["id"],
        author_role=current_user["role"],
        content=payload.content,
        note_type=payload.note_type,
        attachment_hash=payload.attachment_hash,
    )


@router.post("/cases/{case_id}/transition")
def transition_case(
    case_id: str,
    payload: CaseStateTransitionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.MANAGE_CASE_L1_L2)
    return CaseManagementService(db).transition_case_status(
        case_id=case_id,
        target_status=payload.target_status,
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        notes=payload.notes,
        disposition_summary=payload.disposition_summary,
    )


@router.post("/cases/{case_id}/generate-sar")
def generate_sar(
    case_id: str,
    payload: SARGenerationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.DRAFT_SAR)
    return FinCENSarGenerator(db).generate_sar_for_case(
        case_id=case_id,
        prepared_by_user_id=current_user["id"],
        prepared_by_role=current_user["role"],
        filing_type=payload.filing_type,
        custom_why_how_addendum=payload.custom_why_how_addendum,
        auto_submit_for_qa=payload.auto_submit_for_qa,
    )


# ------------------------------------------------------------------------------
# 8. Sanctions Screening & Cryptographic Audit Chain Verification
# ------------------------------------------------------------------------------

@router.post("/sanctions/screen")
def screen_sanctions(
    payload: SanctionsScreenRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.SCREEN_SANCTIONS)
    hits = SanctionsScreeningService(db).screen_entity(
        screened_name=payload.screened_name,
        date_of_birth=payload.date_of_birth,
        country_code=payload.country_code,
        customer_id=payload.customer_id,
        min_similarity_threshold=payload.min_similarity_threshold,
    )
    return {"hit_count": len(hits), "hits": hits}


@router.get("/sanctions/hits")
def list_sanctions_hits(
    disposition: Optional[str] = Query(default=None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.SCREEN_SANCTIONS)
    hits = SanctionsScreeningService(db).list_hits(disposition=disposition)
    return {"count": len(hits), "hits": hits}


@router.post("/sanctions/hits/{hit_id}/resolve")
def resolve_sanctions_hit(
    hit_id: str,
    payload: SanctionsHitDispositionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.SCREEN_SANCTIONS)
    resolved = SanctionsScreeningService(db).resolve_hit(
        hit_id=hit_id,
        disposition=payload.disposition,
        review_notes=payload.review_notes,
        reviewer_user_id=current_user["id"],
    )
    AuditService(db).record_event(
        actor_user_id=current_user["id"],
        actor_role=current_user["role"],
        action="SANCTIONS_HIT_RESOLVED",
        entity_type="SanctionsHit",
        entity_id=hit_id,
        details={"disposition": payload.disposition},
    )
    return resolved


@router.get("/audit/logs")
def get_audit_logs(
    entity_type: Optional[str] = Query(default=None),
    entity_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=500),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VIEW_DASHBOARD)
    logs = AuditService(db).list_logs(entity_type=entity_type, entity_id=entity_id, limit=limit)
    return {"count": len(logs), "audit_logs": logs}


@router.get("/audit/verify")
def verify_audit_chain(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: DatabaseManager = Depends(get_db),
) -> Dict[str, Any]:
    assert_permission(current_user["role"], Permission.VERIFY_AUDIT_LEDGER)
    return AuditService(db).verify_chain_integrity(raise_on_error=False)
