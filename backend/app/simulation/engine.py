"""
RuleForge Shadow-Mode Rule Backtesting & Simulation Studio (`FR-SIM`).
Allows AML Risk Engineers to test candidate parameter modifications against historical
transactions before promoting changes to production.

Computes empirical classification metrics against ground-truth labeled scenarios
(transactions tagged with a criminal `scenario_tag` or linked to confirmed SAR cases):
- True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
- Precision, Recall, F1-Score
- Alert Volume Delta (%) and Estimated Monthly Analyst Hours Saved/Added (assuming 45 mins/alert)
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from backend.app.db.connection import DatabaseManager
from backend.app.repositories.core_repositories import RuleRepository
from backend.app.typologies.engine import TypologyEngine


class RuleSimulationEngine:
    """Executes side-by-side baseline vs. candidate shadow backtests for any typology rule."""

    ANALYST_HOURS_PER_ALERT = 0.75  # 45 minutes average L1+L2 review time per alert

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.rule_repo = RuleRepository(db)
        self.typology_engine = TypologyEngine(db)

    def _determine_ground_truth_positive_accounts(
        self, rule_family: str, context_transactions: List[Dict[str, Any]]
    ) -> Set[str]:
        """
        Identifies accounts that represent true illicit activity for the typology family
        based on ground-truth scenario tags or confirmed SAR filings.
        """
        family_prefix_map = {
            "STRUCTURING": ("SCENARIO_STRUCTURING", "SCENARIO_SMURFING", "SCENARIO_SPLIT"),
            "LAYERING": ("SCENARIO_PASSTHROUGH", "SCENARIO_LAYERING", "SCENARIO_CAROUSEL", "SCENARIO_CRYPTO_EXIT", "SCENARIO_DORMANT"),
            "MULE_NETWORK": ("SCENARIO_FAN_IN", "SCENARIO_FAN_OUT", "SCENARIO_SHARED_DEVICE", "SCENARIO_MULE", "SCENARIO_WASH"),
            "GEOGRAPHIC": ("SCENARIO_HIGH_RISK_GEO", "SCENARIO_OFFSHORE", "SCENARIO_IMPOSSIBLE_TRAVEL", "SCENARIO_TRANSIT"),
            "BEHAVIORAL_FRAUD": ("SCENARIO_ZSCORE_SPIKE", "SCENARIO_ATO_DRAIN", "SCENARIO_ELDER_EXPLOIT", "SCENARIO_MCC_MISMATCH", "SCENARIO_NIGHT_BURST"),
        }
        relevant_prefixes = family_prefix_map.get(rule_family, ())
        positive_accounts: Set[str] = set()

        for tx in context_transactions:
            tag = (tx.get("scenario_tag") or "").upper()
            if not tag or tag == "BASELINE_NORMAL":
                continue
            if any(tag.startswith(p) for p in relevant_prefixes) or tag.startswith("ILLICIT_"):
                positive_accounts.add(tx["account_id"])

        with self.db.connection() as conn:
            sar_rows = conn.execute(
                """
                SELECT DISTINCT a.id AS account_id
                FROM sar_reports s
                JOIN accounts a ON a.customer_id = s.subject_customer_id
                WHERE s.filing_status IN ('APPROVED', 'FILED_WITH_FINCEN')
                """
            ).fetchall()
            for r in sar_rows:
                positive_accounts.add(r["account_id"])

        return positive_accounts

    def run_shadow_backtest(
        self,
        rule_id: str,
        candidate_parameters: Dict[str, Any],
        actor_user_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Runs the specified rule twice over the historical ledger:
        1. Using current active production parameters (`baseline`).
        2. Using `candidate_parameters` (`candidate`).
        Computes confusion matrix, precision/recall/F1, and alert diff.
        """
        rule_meta = self.rule_repo.get_rule(rule_id)
        baseline_params = rule_meta["parameters"]
        ctx = self.typology_engine.build_context()

        baseline_triggers = self.typology_engine.evaluate_single_rule(
            rule_id=rule_id, context=ctx, override_params=baseline_params
        )
        candidate_triggers = self.typology_engine.evaluate_single_rule(
            rule_id=rule_id, context=ctx, override_params=candidate_parameters
        )

        all_accounts = set(ctx.accounts_by_id.keys())
        ground_truth_positives = self._determine_ground_truth_positive_accounts(
            rule_meta["family"], ctx.all_transactions
        )
        # Ensure any account specifically tagged with the exact rule_id in scenario_tag is in ground truth
        for tx in ctx.all_transactions:
            tag = tx.get("scenario_tag") or ""
            if rule_id in tag:
                ground_truth_positives.add(tx["account_id"])

        baseline_flagged = {t.account_id for t in baseline_triggers}
        candidate_flagged = {t.account_id for t in candidate_triggers}

        tp = len(candidate_flagged & ground_truth_positives)
        fp = len(candidate_flagged - ground_truth_positives)
        fn = len(ground_truth_positives - candidate_flagged)
        tn = max(0, len(all_accounts - (candidate_flagged | ground_truth_positives)))

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        f1 = (
            round((2.0 * precision * recall) / (precision + recall), 4)
            if (precision + recall) > 0
            else 0.0
        )

        base_cnt = len(baseline_triggers)
        cand_cnt = len(candidate_triggers)
        volume_delta_pct = (
            round(((cand_cnt - base_cnt) / base_cnt) * 100.0, 2)
            if base_cnt > 0
            else (100.0 if cand_cnt > 0 else 0.0)
        )
        hours_saved = round((base_cnt - cand_cnt) * self.ANALYST_HOURS_PER_ALERT, 2)

        added_accounts = sorted(candidate_flagged - baseline_flagged)
        dropped_accounts = sorted(baseline_flagged - candidate_flagged)

        sample_diff = {
            "newly_captured_accounts": added_accounts[:15],
            "eliminated_alert_accounts": dropped_accounts[:15],
            "baseline_flagged_accounts": sorted(baseline_flagged),
            "candidate_flagged_accounts": sorted(candidate_flagged),
        }

        now_iso = datetime.now(timezone.utc).isoformat()
        sim_id = f"sim-{uuid.uuid4().hex[:12]}"
        run_ref = f"SIM-2026-{uuid.uuid4().hex[:6].upper()}"

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO simulation_runs (
                    id, run_ref, rule_id, created_by, baseline_parameters_json,
                    candidate_parameters_json, transactions_evaluated,
                    baseline_alert_count, candidate_alert_count,
                    true_positives, false_positives, true_negatives, false_negatives,
                    precision_score, recall_score, f1_score,
                    alert_volume_delta_pct, estimated_hours_saved,
                    sample_diff_json, notes, executed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sim_id,
                    run_ref,
                    rule_id,
                    actor_user_id,
                    json.dumps(baseline_params, sort_keys=True),
                    json.dumps(candidate_parameters, sort_keys=True),
                    len(ctx.all_transactions),
                    base_cnt,
                    cand_cnt,
                    tp,
                    fp,
                    tn,
                    fn,
                    precision,
                    recall,
                    f1,
                    volume_delta_pct,
                    hours_saved,
                    json.dumps(sample_diff, sort_keys=True),
                    notes or "Shadow-mode parameter sensitivity simulation",
                    now_iso,
                ),
            )

        return {
            "id": sim_id,
            "run_ref": run_ref,
            "rule_id": rule_id,
            "rule_name": rule_meta["name"],
            "baseline_parameters": baseline_params,
            "candidate_parameters": candidate_parameters,
            "transactions_evaluated": len(ctx.all_transactions),
            "baseline_alert_count": base_cnt,
            "candidate_alert_count": cand_cnt,
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
            "precision_score": precision,
            "recall_score": recall,
            "f1_score": f1,
            "alert_volume_delta_pct": volume_delta_pct,
            "estimated_hours_saved": hours_saved,
            "sample_diff": sample_diff,
            "notes": notes,
            "executed_at": now_iso,
        }

    def list_simulation_runs(self, rule_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        query = "SELECT * FROM simulation_runs WHERE 1=1"
        params: List[Any] = []
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)
        query += " ORDER BY executed_at DESC LIMIT ?"
        params.append(limit)
        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["baseline_parameters"] = json.loads(item.pop("baseline_parameters_json") or "{}")
            item["candidate_parameters"] = json.loads(item.pop("candidate_parameters_json") or "{}")
            item["sample_diff"] = json.loads(item.pop("sample_diff_json") or "{}")
            results.append(item)
        return results
