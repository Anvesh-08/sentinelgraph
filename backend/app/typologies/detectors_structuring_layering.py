"""
Concrete implementations of Family A (Cash Structuring & CTR Evasion: AML-STR-001..005)
and Family B (Rapid Movement of Funds, Layering & Pass-Through: AML-LAY-001..005).
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional

from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext, parse_iso_ts


# ==============================================================================
# FAMILY A — CASH STRUCTURING & CTR EVASION (AML-STR-001 .. AML-STR-005)
# ==============================================================================

class SingleSubCtrStructuringDetector(BaseTypologyDetector):
    rule_id = "AML-STR-001"
    rule_name = "Single-Transaction Sub-CTR Cash Structuring ($8,000–$9,999.99)"
    family = "STRUCTURING"
    default_severity = "HIGH"
    regulatory_citation = "31 CFR 1010.314 / 31 USC 5324"
    default_parameters = {
        "min_amount_usd": 8500.0,
        "max_amount_usd": 9999.99,
        "min_occurrences": 2,
        "window_hours": 168,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params["min_amount_usd"])
        max_amt = float(params["max_amount_usd"])
        min_occ = int(params["min_occurrences"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            cash_band_txs = [
                t for t in txs
                if t["tx_type"] in ("CASH_DEPOSIT", "CASH_WITHDRAWAL")
                and min_amt <= float(t["amount_usd"]) <= max_amt
            ]
            if len(cash_band_txs) < min_occ:
                continue

            # Check sliding window
            for i, start_tx in enumerate(cash_band_txs):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                window_group = [
                    t for t in cash_band_txs[i:]
                    if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta
                ]
                if len(window_group) >= min_occ:
                    total_cash = round(sum(float(t["amount_usd"]) for t in window_group), 2)
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=min(98.0, 75.0 + 6.0 * len(window_group)),
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in window_group],
                            trigger_narrative=(
                                f"Account executed {len(window_group)} cash transactions sized between "
                                f"${min_amt:,.2f} and ${max_amt:,.2f} (totaling ${total_cash:,.2f}) within "
                                f"{params['window_hours']} hours, consistent with deliberate CTR threshold evasion."
                            ),
                            evidence_metrics={
                                "sub_ctr_tx_count": len(window_group),
                                "cumulative_cash_usd": total_cash,
                                "band_min_usd": min_amt,
                                "band_max_usd": max_amt,
                                "window_hours": params["window_hours"],
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class RollingCumulativeCashStructuringDetector(BaseTypologyDetector):
    rule_id = "AML-STR-002"
    rule_name = "Rolling Multi-Transaction Cumulative Cash Structuring (> $10,000)"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "31 CFR 1010.313"
    default_parameters = {
        "single_tx_cap_usd": 9999.99,
        "min_single_tx_usd": 2000.0,
        "cumulative_threshold_usd": 10000.0,
        "min_tx_count": 3,
        "window_hours": 48,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        single_cap = float(params["single_tx_cap_usd"])
        single_min = float(params["min_single_tx_usd"])
        cum_thresh = float(params["cumulative_threshold_usd"])
        min_cnt = int(params["min_tx_count"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            sub_cash = [
                t for t in txs
                if t["tx_type"] in ("CASH_DEPOSIT", "CASH_WITHDRAWAL")
                and single_min <= float(t["amount_usd"]) <= single_cap
            ]
            if len(sub_cash) < min_cnt:
                continue

            for i, start_tx in enumerate(sub_cash):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in sub_cash[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                total_usd = round(sum(float(t["amount_usd"]) for t in win), 2)
                if len(win) >= min_cnt and total_usd >= cum_thresh:
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=92.0,
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Account aggregated ${total_usd:,.2f} across {len(win)} sub-CTR cash transactions "
                                f"within {params['window_hours']} hours (exceeding ${cum_thresh:,.2f} CTR aggregation limit)."
                            ),
                            evidence_metrics={
                                "tx_count": len(win),
                                "cumulative_cash_usd": total_usd,
                                "threshold_usd": cum_thresh,
                                "window_hours": params["window_hours"],
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class MultiBranchCashSmurfingDetector(BaseTypologyDetector):
    rule_id = "AML-STR-003"
    rule_name = "Coordinated Multi-Branch / Multi-Terminal Cash Smurfing"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory FIN-2014-A007"
    default_parameters = {
        "min_distinct_terminals": 3,
        "min_cumulative_usd": 9000.0,
        "max_single_usd": 9999.99,
        "window_hours": 72,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_terms = int(params["min_distinct_terminals"])
        min_cum = float(params["min_cumulative_usd"])
        max_single = float(params["max_single_usd"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            cash_deposits = [
                t for t in txs
                if t["tx_type"] == "CASH_DEPOSIT"
                and float(t["amount_usd"]) <= max_single
                and t.get("branch_or_atm_id")
            ]
            if len(cash_deposits) < min_terms:
                continue

            for i, start_tx in enumerate(cash_deposits):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in cash_deposits[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                terminals = sorted({t["branch_or_atm_id"] for t in win if t.get("branch_or_atm_id")})
                total_usd = round(sum(float(t["amount_usd"]) for t in win), 2)
                if len(terminals) >= min_terms and total_usd >= min_cum:
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=94.0,
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Coordinated funnel-account cash smurfing detected: {len(win)} cash deposits "
                                f"totaling ${total_usd:,.2f} executed across {len(terminals)} distinct branch/ATM terminals "
                                f"({', '.join(terminals)}) within {params['window_hours']} hours."
                            ),
                            evidence_metrics={
                                "distinct_terminals": terminals,
                                "terminal_count": len(terminals),
                                "cumulative_cash_usd": total_usd,
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class SubTravelRuleSplitDetector(BaseTypologyDetector):
    rule_id = "AML-STR-004"
    rule_name = "Sequential Sub-Travel-Rule Wire/ACH Split Structuring ($2,500–$2,999)"
    family = "STRUCTURING"
    default_severity = "MEDIUM"
    regulatory_citation = "31 CFR 1010.410(e)"
    default_parameters = {
        "min_amount_usd": 2500.0,
        "max_amount_usd": 2999.99,
        "min_split_count": 3,
        "window_hours": 48,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params["min_amount_usd"])
        max_amt = float(params["max_amount_usd"])
        min_cnt = int(params["min_split_count"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            splits = [
                t for t in txs
                if t["tx_type"] in ("WIRE_DOMESTIC", "WIRE_INTERNATIONAL", "ACH_DEBIT", "INTERNAL_TRANSFER")
                and t["direction"] == "OUTBOUND"
                and min_amt <= float(t["amount_usd"]) <= max_amt
            ]
            if len(splits) < min_cnt:
                continue

            for i, start_tx in enumerate(splits):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in splits[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                if len(win) >= min_cnt:
                    total_usd = round(sum(float(t["amount_usd"]) for t in win), 2)
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=82.0,
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Account split ${total_usd:,.2f} across {len(win)} sequential outbound transfers "
                                f"between ${min_amt:,.2f} and ${max_amt:,.2f} within {params['window_hours']}h to evade "
                                f"the $3,000 BSA Travel Rule threshold."
                            ),
                            evidence_metrics={
                                "split_transfer_count": len(win),
                                "total_split_usd": total_usd,
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class RoundDollarCashAnomalyDetector(BaseTypologyDetector):
    rule_id = "AML-STR-005"
    rule_name = "High-Frequency Round-Dollar Cash Deposit Anomaly"
    family = "STRUCTURING"
    default_severity = "MEDIUM"
    regulatory_citation = "FFIEC BSA/AML Appendix F"
    default_parameters = {
        "round_modulus_usd": 500.0,
        "min_tx_amount_usd": 1500.0,
        "min_round_count": 4,
        "window_hours": 168,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        mod_val = float(params["round_modulus_usd"])
        min_amt = float(params["min_tx_amount_usd"])
        min_cnt = int(params["min_round_count"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            round_cash = [
                t for t in txs
                if t["tx_type"] == "CASH_DEPOSIT"
                and float(t["amount_usd"]) >= min_amt
                and abs(float(t["amount_usd"]) % mod_val) < 0.01
            ]
            if len(round_cash) < min_cnt:
                continue

            for i, start_tx in enumerate(round_cash):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in round_cash[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                if len(win) >= min_cnt:
                    total_usd = round(sum(float(t["amount_usd"]) for t in win), 2)
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=78.0,
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Account received {len(win)} exact round-dollar cash deposits (multiples of ${mod_val:,.0f}) "
                                f"totaling ${total_usd:,.2f} within {params['window_hours']}h."
                            ),
                            evidence_metrics={
                                "round_cash_count": len(win),
                                "total_round_cash_usd": total_usd,
                                "modulus_usd": mod_val,
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


# ==============================================================================
# FAMILY B — RAPID LAYERING & PASS-THROUGH (AML-LAY-001 .. AML-LAY-005)
# ==============================================================================

class HighVelocityPassThroughDetector(BaseTypologyDetector):
    rule_id = "AML-LAY-001"
    rule_name = "High-Velocity Pass-Through Conduit Account (85%–100% Outflow within 24h)"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Professional Money Laundering Typologies"
    default_parameters = {
        "min_inbound_usd": 15000.0,
        "min_pass_through_ratio": 0.85,
        "max_pass_through_ratio": 1.15,
        "window_hours": 24,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_in = float(params["min_inbound_usd"])
        min_ratio = float(params["min_pass_through_ratio"])
        max_ratio = float(params["max_pass_through_ratio"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            inbounds = [t for t in txs if t["direction"] == "INBOUND"]
            outbounds = [t for t in txs if t["direction"] == "OUTBOUND"]
            if not inbounds or not outbounds:
                continue

            for in_tx in inbounds:
                t0 = parse_iso_ts(in_tx["tx_timestamp"])
                in_win = [
                    t for t in inbounds
                    if timedelta(0) <= (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
                ]
                out_win = [
                    t for t in outbounds
                    if timedelta(0) <= (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
                ]
                sum_in = sum(float(t["amount_usd"]) for t in in_win)
                sum_out = sum(float(t["amount_usd"]) for t in out_win)
                if sum_in < min_in or not out_win:
                    continue

                ratio = sum_out / sum_in
                if min_ratio <= ratio <= max_ratio:
                    tx_ids = list({t["id"] for t in (in_win + out_win)})
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=93.0,
                            customer_id=in_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=tx_ids,
                            trigger_narrative=(
                                f"Rapid pass-through conduit behavior: Account received ${sum_in:,.2f} inbound and "
                                f"wired/transferred out ${sum_out:,.2f} ({ratio * 100:.1f}% pass-through ratio) "
                                f"within {params['window_hours']} hours."
                            ),
                            evidence_metrics={
                                "inbound_usd": round(sum_in, 2),
                                "outbound_usd": round(sum_out, 2),
                                "pass_through_ratio": round(ratio, 4),
                                "window_hours": params["window_hours"],
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class MultiHopLayeringChainDetector(BaseTypologyDetector):
    rule_id = "AML-LAY-002"
    rule_name = "Multi-Hop Internal Layering Chain (A -> B -> C within 48h)"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN SAR Activity Review — Multi-Account Layering"
    default_parameters = {
        "min_hop_amount_usd": 8000.0,
        "max_hop_delay_hours": 48,
        "min_retention_decay_ratio": 0.70,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params["min_hop_amount_usd"])
        max_delay = timedelta(hours=float(params["max_hop_delay_hours"]))
        min_decay = float(params["min_retention_decay_ratio"])

        # Inspect internal outbound transfers where counterparty_account_id is populated
        hop_edges = [
            t for t in context.all_transactions
            if t["direction"] == "OUTBOUND"
            and t.get("counterparty_account_id")
            and float(t["amount_usd"]) >= min_amt
        ]
        by_src: Dict[str, List[Dict[str, Any]]] = {}
        for edge in hop_edges:
            by_src.setdefault(edge["account_id"], []).append(edge)

        results: List[RuleTriggerResult] = []
        seen_accounts = set()

        for tx1 in hop_edges:
            acct_a = tx1["account_id"]
            acct_b = tx1["counterparty_account_id"]
            if acct_a in seen_accounts or not acct_b:
                continue
            t1 = parse_iso_ts(tx1["tx_timestamp"])
            amt1 = float(tx1["amount_usd"])

            for tx2 in by_src.get(acct_b, []):
                acct_c = tx2["counterparty_account_id"]
                if not acct_c or acct_c in (acct_a, acct_b):
                    continue
                t2 = parse_iso_ts(tx2["tx_timestamp"])
                amt2 = float(tx2["amount_usd"])
                if timedelta(0) <= (t2 - t1) <= max_delay and (amt2 / amt1) >= min_decay:
                    # Check optional 3rd hop C -> D
                    hop_txs = [tx1, tx2]
                    chain_nodes = [acct_a, acct_b, acct_c]
                    for tx3 in by_src.get(acct_c, []):
                        t3 = parse_iso_ts(tx3["tx_timestamp"])
                        if timedelta(0) <= (t3 - t2) <= max_delay and (float(tx3["amount_usd"]) / amt2) >= min_decay:
                            hop_txs.append(tx3)
                            chain_nodes.append(tx3["counterparty_account_id"])
                            break

                    seen_accounts.add(acct_a)
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=95.0,
                            customer_id=tx1["customer_id"],
                            account_id=acct_a,
                            triggered_transaction_ids=[t["id"] for t in hop_txs],
                            trigger_narrative=(
                                f"Multi-hop layering chain detected across {len(chain_nodes)} accounts "
                                f"({' -> '.join(chain_nodes)}): initial transfer of ${amt1:,.2f} rapidly relayed "
                                f"downstream (${amt2:,.2f}) within {params['max_hop_delay_hours']} hours."
                            ),
                            evidence_metrics={
                                "chain_accounts": chain_nodes,
                                "hop_count": len(hop_txs),
                                "initial_amount_usd": amt1,
                                "relayed_amount_usd": amt2,
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class CircularRoundTrippingDetector(BaseTypologyDetector):
    rule_id = "AML-LAY-003"
    rule_name = "Circular Round-Tripping / Carousel Fund Flow"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Trade-Based & Round-Tripping Money Laundering Indicators"
    default_parameters = {
        "min_cycle_amount_usd": 5000.0,
        "max_cycle_length": 5,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params["min_cycle_amount_usd"])
        max_len = int(params["max_cycle_length"])

        edges = [
            t for t in context.all_transactions
            if t["direction"] == "OUTBOUND"
            and t.get("counterparty_account_id")
            and float(t["amount_usd"]) >= min_amt
        ]
        adj: Dict[str, List[Dict[str, Any]]] = {}
        for e in edges:
            adj.setdefault(e["account_id"], []).append(e)

        results: List[RuleTriggerResult] = []
        reported_cycles = set()

        for start_acct in sorted(adj.keys()):
            # DFS for temporal cycle returning to start_acct
            stack: List[ tuple ] = [(start_acct, [start_acct], [], None)]
            while stack:
                curr, path_nodes, path_txs, last_ts = stack.pop()
                if len(path_txs) >= max_len:
                    continue
                for edge in adj.get(curr, []):
                    edge_ts = parse_iso_ts(edge["tx_timestamp"])
                    if last_ts is not None and edge_ts < last_ts:
                        continue
                    nxt = edge["counterparty_account_id"]
                    if nxt == start_acct and len(path_txs) >= 2:
                        cycle_txs = path_txs + [edge]
                        canonical_key = tuple(sorted(path_nodes))
                        if canonical_key not in reported_cycles:
                            reported_cycles.add(canonical_key)
                            total_cycled = round(sum(float(t["amount_usd"]) for t in cycle_txs), 2)
                            cust_id = context.accounts_by_id.get(start_acct, {}).get("customer_id", cycle_txs[0]["customer_id"])
                            results.append(
                                RuleTriggerResult(
                                    rule_id=self.rule_id,
                                    rule_name=self.rule_name,
                                    family=self.family,
                                    severity=self.default_severity,
                                    confidence_score=97.0,
                                    customer_id=cust_id,
                                    account_id=start_acct,
                                    triggered_transaction_ids=[t["id"] for t in cycle_txs],
                                    trigger_narrative=(
                                        f"Circular carousel round-tripping detected across {len(path_nodes)}-account ring "
                                        f"({' -> '.join(path_nodes + [start_acct])}) moving ${total_cycled:,.2f} in cumulative "
                                        f"layered volume back to originator."
                                    ),
                                    evidence_metrics={
                                        "cycle_accounts": path_nodes + [start_acct],
                                        "cycle_length": len(cycle_txs),
                                        "total_cycled_usd": total_cycled,
                                    },
                                    regulatory_citation=self.regulatory_citation,
                                )
                            )
                    elif nxt not in path_nodes:
                        stack.append((nxt, path_nodes + [nxt], path_txs + [edge], edge_ts))
        return results


class DormantAccountAwakeningDetector(BaseTypologyDetector):
    rule_id = "AML-LAY-004"
    rule_name = "Dormant Account Sudden High-Value Awakening"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FFIEC BSA/AML Appendix F"
    default_parameters = {
        "min_dormant_gap_days": 45,
        "min_awakening_amount_usd": 12000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_gap_days = float(params["min_dormant_gap_days"])
        min_amt = float(params["min_awakening_amount_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            acct = context.accounts_by_id.get(acct_id, {})
            if len(txs) >= 2:
                for idx in range(1, len(txs)):
                    prev_dt = parse_iso_ts(txs[idx - 1]["tx_timestamp"])
                    curr_dt = parse_iso_ts(txs[idx]["tx_timestamp"])
                    gap_days = (curr_dt - prev_dt).total_seconds() / 86400.0
                    amt = float(txs[idx]["amount_usd"])
                    if gap_days >= min_gap_days and amt >= min_amt:
                        results.append(
                            RuleTriggerResult(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                family=self.family,
                                severity=self.default_severity,
                                confidence_score=86.0,
                                customer_id=txs[idx]["customer_id"],
                                account_id=acct_id,
                                triggered_transaction_ids=[txs[idx - 1]["id"], txs[idx]["id"]],
                                trigger_narrative=(
                                    f"Account remained inactive for {gap_days:.1f} days before suddenly executing "
                                    f"a ${amt:,.2f} {txs[idx]['tx_type']} transaction."
                                ),
                                evidence_metrics={
                                    "dormant_gap_days": round(gap_days, 1),
                                    "awakening_amount_usd": amt,
                                    "account_status": acct.get("status", "ACTIVE"),
                                },
                                regulatory_citation=self.regulatory_citation,
                            )
                        )
                        break
        return results


class FiatToCryptoExitDetector(BaseTypologyDetector):
    rule_id = "AML-LAY-005"
    rule_name = "Immediate Fiat-to-Crypto Cross-Channel Exit Layering"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN Advisory FIN-2019-A003"
    default_parameters = {
        "min_crypto_outflow_usd": 7500.0,
        "min_conversion_ratio": 0.70,
        "window_hours": 24,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_crypto = float(params["min_crypto_outflow_usd"])
        min_ratio = float(params["min_conversion_ratio"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            fiat_in = [
                t for t in txs
                if t["direction"] == "INBOUND" and t["tx_type"] in ("WIRE_DOMESTIC", "WIRE_INTERNATIONAL", "ACH_CREDIT", "CASH_DEPOSIT")
            ]
            crypto_out = [
                t for t in txs
                if t["direction"] == "OUTBOUND" and t["tx_type"] == "CRYPTO_EXCHANGE"
            ]
            if not fiat_in or not crypto_out:
                continue

            for f_tx in fiat_in:
                t0 = parse_iso_ts(f_tx["tx_timestamp"])
                c_win = [
                    c for c in crypto_out
                    if timedelta(0) <= (parse_iso_ts(c["tx_timestamp"]) - t0) <= win_delta
                ]
                crypto_sum = round(sum(float(c["amount_usd"]) for c in c_win), 2)
                fiat_amt = float(f_tx["amount_usd"])
                if crypto_sum >= min_crypto and fiat_amt > 0 and (crypto_sum / fiat_amt) >= min_ratio:
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=89.0,
                            customer_id=f_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[f_tx["id"]] + [c["id"] for c in c_win],
                            trigger_narrative=(
                                f"Inbound fiat funding of ${fiat_amt:,.2f} ({f_tx['tx_type']}) was converted within "
                                f"{params['window_hours']}h into ${crypto_sum:,.2f} of outbound cryptocurrency exchange transfers "
                                f"({(crypto_sum / fiat_amt) * 100:.1f}% conversion ratio)."
                            ),
                            evidence_metrics={
                                "fiat_inbound_usd": fiat_amt,
                                "crypto_outbound_usd": crypto_sum,
                                "conversion_ratio": round(crypto_sum / fiat_amt, 4),
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results
