"""
Central Typology Registry, Batch/Real-Time Evaluation Orchestrator, and CTR Aggregator.
Coordinates all 25 AML & Fraud detectors, deduplicates alert generation, updates transaction
flag statuses, and automatically generates FinCEN Currency Transaction Reports (CTRs)
when daily cash exceeds $10,000.00.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from backend.app.db.connection import DatabaseManager
from backend.app.models.domain import RuleTriggerResult
from backend.app.repositories.core_repositories import RuleRepository
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext
from backend.app.typologies.catalog import DEFAULT_TYPOLOGY_RULES
from backend.app.typologies.detectors_network_geo_fraud import (
    AccountTakeoverRapidDrainDetector,
    CommercialKybMccMismatchDetector,
    CrossBorderRemittanceBurstDetector,
    ElderFinancialExploitationDetector,
    ExtremeVelocityZScoreDetector,
    FanInCollectorHubDetector,
    FanOutDistributorHubDetector,
    HighRiskContagionTransferDetector,
    HighRiskJurisdictionWireDetector,
    ImpossibleTravelVelocityDetector,
    OffHoursAutomatedBurstDetector,
    OffshoreTaxHavenLayeringDetector,
    ReciprocalWashTransferDetector,
    SanctionsAdjacentTransitRoutingDetector,
    SharedDeviceOrIpRingDetector,
)
from backend.app.typologies.detectors_structuring_layering import (
    CircularRoundTrippingDetector,
    DormantAccountAwakeningDetector,
    FiatToCryptoExitDetector,
    HighVelocityPassThroughDetector,
    MultiBranchCashSmurfingDetector,
    MultiHopLayeringChainDetector,
    RollingCumulativeCashStructuringDetector,
    RoundDollarCashAnomalyDetector,
    SingleSubCtrStructuringDetector,
    SubTravelRuleSplitDetector,
)


ALL_DETECTOR_CLASSES: List[type] = [
    SingleSubCtrStructuringDetector,
    RollingCumulativeCashStructuringDetector,
    MultiBranchCashSmurfingDetector,
    SubTravelRuleSplitDetector,
    RoundDollarCashAnomalyDetector,
    HighVelocityPassThroughDetector,
    MultiHopLayeringChainDetector,
    CircularRoundTrippingDetector,
    DormantAccountAwakeningDetector,
    FiatToCryptoExitDetector,
    FanInCollectorHubDetector,
    FanOutDistributorHubDetector,
    SharedDeviceOrIpRingDetector,
    HighRiskContagionTransferDetector,
    ReciprocalWashTransferDetector,
    HighRiskJurisdictionWireDetector,
    OffshoreTaxHavenLayeringDetector,
    ImpossibleTravelVelocityDetector,
    CrossBorderRemittanceBurstDetector,
    SanctionsAdjacentTransitRoutingDetector,
    ExtremeVelocityZScoreDetector,
    AccountTakeoverRapidDrainDetector,
    ElderFinancialExploitationDetector,
    CommercialKybMccMismatchDetector,
    OffHoursAutomatedBurstDetector,
]


class TypologyEngine:
    """Orchestrates rule catalog synchronization, ledger evaluation, alert persistence, and CTR generation."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.rule_repo = RuleRepository(db)
        self.detectors: Dict[str, BaseTypologyDetector] = {
            cls.rule_id: cls() for cls in ALL_DETECTOR_CLASSES
        }

    def ensure_default_rules_seeded(self) -> int:
        """Inserts any missing rules from the 25-rule catalog into `typology_rules`."""
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        with self.db.connection() as conn:
            for item in DEFAULT_TYPOLOGY_RULES:
                existing = conn.execute(
                    "SELECT id FROM typology_rules WHERE id = ?", (item["id"],)
                ).fetchone()
                if not existing:
                    conn.execute(
                        """
                        INSERT INTO typology_rules (
                            id, name, family, severity, description, parameters_json,
                            is_enabled, version, regulatory_citation, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
                        """,
                        (
                            item["id"],
                            item["name"],
                            item["family"],
                            item["severity"],
                            item["description"],
                            json.dumps(item["parameters"], sort_keys=True),
                            item["regulatory_citation"],
                            now,
                        ),
                    )
                    inserted += 1
        return inserted

    def build_context(self) -> TypologyEvaluationContext:
        with self.db.connection() as conn:
            cust_rows = conn.execute("SELECT * FROM customers").fetchall()
            acct_rows = conn.execute("SELECT * FROM accounts").fetchall()
            tx_rows = conn.execute("SELECT * FROM transactions ORDER BY tx_timestamp ASC").fetchall()
            flagged_rows = conn.execute(
                "SELECT DISTINCT account_id FROM alerts WHERE status != 'DISMISSED_FALSE_POSITIVE'"
            ).fetchall()

        customers_by_id = {r["id"]: dict(r) for r in cust_rows}
        accounts_by_id = {r["id"]: dict(r) for r in acct_rows}
        transactions = [dict(r) for r in tx_rows]
        flagged_accts = {r["account_id"] for r in flagged_rows}

        return TypologyEvaluationContext(
            customers_by_id=customers_by_id,
            accounts_by_id=accounts_by_id,
            transactions=transactions,
            flagged_account_ids=flagged_accts,
        )

    def evaluate_single_rule(
        self,
        rule_id: str,
        context: Optional[TypologyEvaluationContext] = None,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        detector = self.detectors.get(rule_id)
        if not detector:
            raise ValueError(f"Unknown typology detector rule_id '{rule_id}'.")
        ctx = context or self.build_context()
        return detector.evaluate(ctx, override_params=override_params)

    def evaluate_all_rules(self, persist_alerts: bool = True) -> Dict[str, Any]:
        """
        Runs all enabled typology rules against the transaction ledger, persists new alerts
        (idempotently avoiding duplicate alerts for the same account + rule_id), and runs CTR aggregation.
        """
        self.ensure_default_rules_seeded()
        ctx = self.build_context()
        active_rules = self.rule_repo.list_rules(enabled_only=True)

        all_triggers: List[RuleTriggerResult] = []
        for rule_meta in active_rules:
            r_id = rule_meta["id"]
            detector = self.detectors.get(r_id)
            if not detector:
                continue
            triggers = detector.evaluate(ctx, override_params=rule_meta["parameters"])
            for trig in triggers:
                trig.severity = rule_meta["severity"]
            all_triggers.extend(triggers)

        new_alerts_created = 0
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        if persist_alerts:
            with self.db.connection() as conn:
                existing_pairs = {
                    (r["account_id"], r["rule_id"])
                    for r in conn.execute("SELECT account_id, rule_id FROM alerts").fetchall()
                }
                seq_row = conn.execute("SELECT COUNT(*) AS cnt FROM alerts").fetchone()
                seq_num = int(seq_row["cnt"]) if seq_row else 0

                for trig in all_triggers:
                    if (trig.account_id, trig.rule_id) in existing_pairs:
                        continue
                    existing_pairs.add((trig.account_id, trig.rule_id))
                    seq_num += 1
                    alert_id = f"alt-{uuid.uuid4().hex[:12]}"
                    alert_ref = f"ALT-2026-{seq_num:05d}"

                    sla_hours = 24 if trig.severity == "CRITICAL" else (48 if trig.severity == "HIGH" else 72)
                    sla_due = (now_dt + timedelta(hours=sla_hours)).isoformat()

                    conn.execute(
                        """
                        INSERT INTO alerts (
                            id, alert_ref, customer_id, account_id, rule_id, rule_version,
                            severity, risk_score, status, trigger_narrative,
                            evidence_metrics_json, sla_due_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, 'NEW', ?, ?, ?, ?)
                        """,
                        (
                            alert_id,
                            alert_ref,
                            trig.customer_id,
                            trig.account_id,
                            trig.rule_id,
                            trig.severity,
                            round(trig.confidence_score, 2),
                            trig.trigger_narrative,
                            json.dumps(trig.evidence_metrics, sort_keys=True),
                            sla_due,
                            now_iso,
                        ),
                    )
                    for tx_id in trig.triggered_transaction_ids:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO alert_transactions (alert_id, transaction_id, contribution_weight)
                            VALUES (?, ?, 1.0)
                            """,
                            (alert_id, tx_id),
                        )
                        conn.execute("UPDATE transactions SET is_flagged = 1 WHERE id = ?", (tx_id,))
                    new_alerts_created += 1

        ctrs_created = self.generate_ctr_reports(ctx) if persist_alerts else 0
        return {
            "rules_evaluated": len(active_rules),
            "total_triggers_detected": len(all_triggers),
            "new_alerts_persisted": new_alerts_created,
            "ctr_reports_generated": ctrs_created,
        }

    def generate_ctr_reports(self, context: Optional[TypologyEvaluationContext] = None) -> int:
        """
        FinCEN CTR Rule (31 CFR 1010.311): Automatically generates a Currency Transaction Report
        whenever a customer aggregates > $10,000.00 in cash deposits or cash withdrawals in a single calendar day.
        """
        ctx = context or self.build_context()
        daily_cash: Dict[tuple, List[Dict[str, Any]]] = {}
        for tx in ctx.all_transactions:
            if tx["tx_type"] not in ("CASH_DEPOSIT", "CASH_WITHDRAWAL"):
                continue
            day_str = tx["tx_timestamp"][:10]
            key = (tx["customer_id"], tx["account_id"], day_str)
            daily_cash.setdefault(key, []).append(tx)

        created = 0
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.db.connection() as conn:
            existing_ctrs = {
                (r["customer_id"], r["account_id"], r["aggregation_date"])
                for r in conn.execute("SELECT customer_id, account_id, aggregation_date FROM ctr_reports").fetchall()
            }
            cnt_row = conn.execute("SELECT COUNT(*) AS cnt FROM ctr_reports").fetchone()
            seq = int(cnt_row["cnt"]) if cnt_row else 0

            for (cust_id, acct_id, day_str), txs in daily_cash.items():
                cash_in = round(
                    sum(float(t["amount_usd"]) for t in txs if t["tx_type"] == "CASH_DEPOSIT"), 2
                )
                cash_out = round(
                    sum(float(t["amount_usd"]) for t in txs if t["tx_type"] == "CASH_WITHDRAWAL"), 2
                )
                if cash_in > 10000.0 or cash_out > 10000.0:
                    if (cust_id, acct_id, day_str) in existing_ctrs:
                        continue
                    seq += 1
                    ctr_id = f"ctr-{uuid.uuid4().hex[:10]}"
                    ctr_ref = f"CTR-2026-{seq:05d}"
                    conn.execute(
                        """
                        INSERT INTO ctr_reports (
                            id, ctr_ref, customer_id, account_id, aggregation_date,
                            total_cash_in_usd, total_cash_out_usd, transaction_ids_json,
                            filing_status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'GENERATED', ?)
                        """,
                        (
                            ctr_id,
                            ctr_ref,
                            cust_id,
                            acct_id,
                            day_str,
                            cash_in,
                            cash_out,
                            json.dumps([t["id"] for t in txs]),
                            now_iso,
                        ),
                    )
                    created += 1
        return created
