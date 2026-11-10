"""
Statistical Quality Assurance (QA) Sampling, Investigator SLA Analytics,
and Adversarial Red-Team Financial Crime Stress-Testing Engine.
"""
import math
from typing import Any, Dict, List

from backend.app.db.connection import DatabaseManager
from backend.app.typologies.engine import TypologyEngine
from backend.app.typologies.global_registry import get_100_detector_map


class QaAndRedTeamAnalyticsEngine:
    """Computes risk-stratified QA sample queues, investigator metrics, and adversarial evasion resilience."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def generate_risk_stratified_qa_sample(self, sample_rate_critical: float = 1.0, sample_rate_high: float = 0.50) -> Dict[str, Any]:
        with self.db.connection() as conn:
            cases = [dict(r) for r in conn.execute("SELECT * FROM cases ORDER BY total_suspicious_amount_usd DESC").fetchall()]
            dismissed_alerts = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM alerts WHERE status = 'DISMISSED_FALSE_POSITIVE' ORDER BY risk_score DESC"
                ).fetchall()
            ]

        selected_cases: List[Dict[str, Any]] = []
        for idx, c in enumerate(cases):
            if c["priority"] == "CRITICAL" and sample_rate_critical >= 1.0:
                selected_cases.append({**c, "qa_selection_reason": "100% Mandatory CRITICAL Case QA Audit"})
            elif idx % max(1, int(round(1.0 / max(0.1, sample_rate_high)))) == 0:
                selected_cases.append({**c, "qa_selection_reason": "Risk-Stratified High-Priority Sample"})

        return {
            "total_cases_population": len(cases),
            "selected_qa_case_count": len(selected_cases),
            "dismissed_false_positive_audit_pool": len(dismissed_alerts),
            "qa_sample_cases": selected_cases,
        }

    def run_adversarial_red_team_evasion_suite(self) -> Dict[str, Any]:
        """
        Tests threshold sensitivity across structuring, pass-through layering, and mule fan-in rules
        when an adversary attempts threshold shaving (e.g., shifting deposits from $9,500 to $8,400
        or delaying pass-through wires from 18h to 26h).
        """
        engine = TypologyEngine(self.db)
        ctx = engine.build_context()
        detector_map = get_100_detector_map()

        scenarios = [
            (
                "Structuring Threshold Shaving ($8,500 -> $7,800)",
                "AML-STR-001",
                {"min_amount_usd": 8500.0, "max_amount_usd": 9999.99, "min_occurrences": 2, "window_hours": 168},
                {"min_amount_usd": 7500.0, "max_amount_usd": 9999.99, "min_occurrences": 2, "window_hours": 168},
            ),
            (
                "Pass-Through Delay Evasion (24h -> 36h Window)",
                "AML-LAY-001",
                {"min_inbound_usd": 15000.0, "min_pass_through_ratio": 0.85, "max_pass_through_ratio": 1.15, "window_hours": 24},
                {"min_inbound_usd": 12000.0, "min_pass_through_ratio": 0.80, "max_pass_through_ratio": 1.20, "window_hours": 36},
            ),
            (
                "Mule Collector Sender Dilution (4 -> 3 Senders)",
                "AML-NET-001",
                {"min_distinct_senders": 4, "min_total_inbound_usd": 12000.0, "window_hours": 72},
                {"min_distinct_senders": 3, "min_total_inbound_usd": 10000.0, "window_hours": 96},
            ),
        ]

        results: List[Dict[str, Any]] = []
        for title, rule_id, prod_params, hardened_params in scenarios:
            det = detector_map[rule_id]
            prod_hits = det.evaluate(ctx, override_params=prod_params)
            hard_hits = det.evaluate(ctx, override_params=hardened_params)
            results.append(
                {
                    "scenario_name": title,
                    "rule_id": rule_id,
                    "production_captures": len(prod_hits),
                    "hardened_captures": len(hard_hits),
                    "incremental_evasion_catch": max(0, len(hard_hits) - len(prod_hits)),
                }
            )

        return {
            "red_team_scenarios_executed": len(results),
            "results": results,
        }
