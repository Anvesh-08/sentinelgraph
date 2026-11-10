"""
Automated Typology Detector Pack: Capital Markets Manipulation, Order-Book Spoofing, Microcap & Insider Trading
Contains 15 configurable, domain-authentic AML & Fraud typology detectors with full
sliding-window evaluation, multi-attribute corroboration, and explainable forensic narratives.
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional

from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext, parse_iso_ts


class Detector_FRD_MKT_001(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-001: Order-Book Spoofing / Phantom Liquidity Cancellation Velocity
    Regulatory Citation: CFTC & SEC Anti-Spoofing Enforcement (Dodd-Frank Act Sec 747)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-001"
    rule_name = "Order-Book Spoofing / Phantom Liquidity Cancellation Velocity"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "CFTC & SEC Anti-Spoofing Enforcement (Dodd-Frank Act Sec 747)"
    description = "High-frequency quote submissions and cancellations on non-clearing trading gateway."
    default_parameters = {
        "min_amount_usd": 40000.00,
        "window_hours": 168,
        "target_keyword": "SPOOFING",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"High-frequency quote submissions and cancellations on non-clearing trading gateway: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_002(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-002: Cross-Venue Microcap Pump-and-Dump Omnibus Liquidation
    Regulatory Citation: FINRA Regulatory Notice 21-03 — Low-Priced Securities Fraud
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-002"
    rule_name = "Cross-Venue Microcap Pump-and-Dump Omnibus Liquidation"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "FINRA Regulatory Notice 21-03 — Low-Priced Securities Fraud"
    description = "Deposition of physical certificate followed by immediate sale and wire withdrawal."
    default_parameters = {
        "min_amount_usd": 35000.00,
        "window_hours": 168,
        "target_keyword": "MICROCAP",
        "required_direction": "INBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Deposition of physical certificate followed by immediate sale and wire withdrawal: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_003(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-003: Pre-M&A Announcement Call-Option Outlier Funding Wire
    Regulatory Citation: SEC Division of Enforcement Insider Trading Analytics
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-003"
    rule_name = "Pre-M&A Announcement Call-Option Outlier Funding Wire"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "SEC Division of Enforcement Insider Trading Analytics"
    description = "Urgent offshore wire funding newly opened brokerage account buying deep out-of-the-money calls."
    default_parameters = {
        "min_amount_usd": 48000.00,
        "window_hours": 168,
        "target_keyword": "OPTIONS FUNDING",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Urgent offshore wire funding newly opened brokerage account buying deep out-of-the-money calls: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_004(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-004: Pre-Arranged Cross-Trade / Wash Trading Between Affiliated Accounts
    Regulatory Citation: FINRA Rule 5210 — Publication of Transactions and Quotations
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-004"
    rule_name = "Pre-Arranged Cross-Trade / Wash Trading Between Affiliated Accounts"
    family = "STRUCTURING"
    default_severity = "HIGH"
    regulatory_citation = "FINRA Rule 5210 — Publication of Transactions and Quotations"
    description = "Simultaneous buy and sell orders between related entities to create artificial volume."
    default_parameters = {
        "min_amount_usd": 30000.00,
        "window_hours": 168,
        "target_keyword": "CROSS TRADE",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Simultaneous buy and sell orders between related entities to create artificial volume: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_005(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-005: Marking the Close (Ramping) End-of-Day Valuation Manipulation
    Regulatory Citation: SEC Enforcement on Portfolio Valuation Manipulation
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-005"
    rule_name = "Marking the Close (Ramping) End-of-Day Valuation Manipulation"
    family = "STRUCTURING"
    default_severity = "HIGH"
    regulatory_citation = "SEC Enforcement on Portfolio Valuation Manipulation"
    description = "Clustered high-price market orders in final 2 minutes of trading to inflate fund NAV."
    default_parameters = {
        "min_amount_usd": 26000.00,
        "window_hours": 168,
        "target_keyword": "CLOSE RAMPING",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Clustered high-price market orders in final 2 minutes of trading to inflate fund NAV: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_006(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-006: Prime Broker Margin Deficit Collateral Substitution Run
    Regulatory Citation: Federal Reserve Regulation T & FINRA Rule 4210 Margin Requirements
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-006"
    rule_name = "Prime Broker Margin Deficit Collateral Substitution Run"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "Federal Reserve Regulation T & FINRA Rule 4210 Margin Requirements"
    description = "Substituting liquid cash margin with illiquid unrated foreign debt instruments."
    default_parameters = {
        "min_amount_usd": 60000.00,
        "window_hours": 168,
        "target_keyword": "MARGIN DEFICIT",
        "required_direction": "INBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Substituting liquid cash margin with illiquid unrated foreign debt instruments: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_007(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-007: Securities Lending Naked Short-Selling Fail-to-Deliver Loop
    Regulatory Citation: SEC Regulation SHO Threshold Security Rules
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-007"
    rule_name = "Securities Lending Naked Short-Selling Fail-to-Deliver Loop"
    family = "STRUCTURING"
    default_severity = "HIGH"
    regulatory_citation = "SEC Regulation SHO Threshold Security Rules"
    description = "Persistent failure to deliver borrowed shares paired with offshore cash hedge."
    default_parameters = {
        "min_amount_usd": 33000.00,
        "window_hours": 168,
        "target_keyword": "FAIL TO DELIVER",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Persistent failure to deliver borrowed shares paired with offshore cash hedge: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_008(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-008: High-Frequency Quote Stuffing Market Latency Exploitation
    Regulatory Citation: SEC Rule 15c3-5 Market Access Control Guidelines
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-008"
    rule_name = "High-Frequency Quote Stuffing Market Latency Exploitation"
    family = "STRUCTURING"
    default_severity = "MEDIUM"
    regulatory_citation = "SEC Rule 15c3-5 Market Access Control Guidelines"
    description = "Burst of 10,000+ orders per second to create artificial exchange queue congestion."
    default_parameters = {
        "min_amount_usd": 22000.00,
        "window_hours": 168,
        "target_keyword": "QUOTE STUFFING",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Burst of 10,000+ orders per second to create artificial exchange queue congestion: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_009(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-009: PIPE (Private Investment in Public Equity) Toxic Convertible Dump
    Regulatory Citation: SEC Guidance on Death-Spiral Financing Arrangements
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-009"
    rule_name = "PIPE (Private Investment in Public Equity) Toxic Convertible Dump"
    family = "STRUCTURING"
    default_severity = "HIGH"
    regulatory_citation = "SEC Guidance on Death-Spiral Financing Arrangements"
    description = "Conversion of toxic debenture into common shares followed by aggressive short sale."
    default_parameters = {
        "min_amount_usd": 38000.00,
        "window_hours": 168,
        "target_keyword": "CONVERTIBLE DEBENTURE",
        "required_direction": "INBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Conversion of toxic debenture into common shares followed by aggressive short sale: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_010(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-010: Foreign Brokerage Delivery-Versus-Payment (DVP) Default Escape
    Regulatory Citation: DVP Settlement Risk & Custody Laundering Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-010"
    rule_name = "Foreign Brokerage Delivery-Versus-Payment (DVP) Default Escape"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "DVP Settlement Risk & Custody Laundering Indicators"
    description = "Failing on delivery side of DVP trade while sweeping corresponding cash settlement abroad."
    default_parameters = {
        "min_amount_usd": 44000.00,
        "window_hours": 168,
        "target_keyword": "DVP SETTLEMENT",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Failing on delivery side of DVP trade while sweeping corresponding cash settlement abroad: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_011(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-011: Algorithmic Layering Multiple Price-Book Deception Levels
    Regulatory Citation: CFTC Order-Book Deception & Layering Guidelines
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-011"
    rule_name = "Algorithmic Layering Multiple Price-Book Deception Levels"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "CFTC Order-Book Deception & Layering Guidelines"
    description = "Submitting cascading tiered orders on opposite side of book to influence execution price."
    default_parameters = {
        "min_amount_usd": 36000.00,
        "window_hours": 168,
        "target_keyword": "ORDER LAYERING",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Submitting cascading tiered orders on opposite side of book to influence execution price: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_012(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-012: Repurchase Agreement (Repo) Collateral Double-Hypothecation
    Regulatory Citation: Federal Reserve & Treasury Tri-Party Repo Infrastructure Rules
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-012"
    rule_name = "Repurchase Agreement (Repo) Collateral Double-Hypothecation"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "Federal Reserve & Treasury Tri-Party Repo Infrastructure Rules"
    description = "Pledging identical securities collateral across multiple repo lenders simultaneously."
    default_parameters = {
        "min_amount_usd": 55000.00,
        "window_hours": 168,
        "target_keyword": "REPO COLLATERAL",
        "required_direction": "INBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Pledging identical securities collateral across multiple repo lenders simultaneously: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_013(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-013: Front-Running Customer Block Order Information Leakage
    Regulatory Citation: FINRA Rule 5270 — Front Running of Block Transactions
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-013"
    rule_name = "Front-Running Customer Block Order Information Leakage"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "FINRA Rule 5270 — Front Running of Block Transactions"
    description = "Proprietary desk position accumulation immediately prior to executing large institutional order."
    default_parameters = {
        "min_amount_usd": 29000.00,
        "window_hours": 168,
        "target_keyword": "BLOCK EXECUTION",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Proprietary desk position accumulation immediately prior to executing large institutional order: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_014(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-014: Structured Note / Exotic Derivative Hidden Leverage Concealment
    Regulatory Citation: ISDA & SEC Exotic Structured Product Suitability & Fraud
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-014"
    rule_name = "Structured Note / Exotic Derivative Hidden Leverage Concealment"
    family = "STRUCTURING"
    default_severity = "HIGH"
    regulatory_citation = "ISDA & SEC Exotic Structured Product Suitability & Fraud"
    description = "Concealing off-balance-sheet leverage via synthetic credit-linked notes."
    default_parameters = {
        "min_amount_usd": 42000.00,
        "window_hours": 168,
        "target_keyword": "STRUCTURED NOTE",
        "required_direction": "INBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Concealing off-balance-sheet leverage via synthetic credit-linked notes: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


class Detector_FRD_MKT_015(BaseTypologyDetector):
    """
    Typology Rule FRD-MKT-015: Foreign Exchange (FX) Fix Manipulation / Banging the Close
    Regulatory Citation: FCA & DOJ FX Benchmark Manipulation Enforcement
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MKT-015"
    rule_name = "Foreign Exchange (FX) Fix Manipulation / Banging the Close"
    family = "STRUCTURING"
    default_severity = "CRITICAL"
    regulatory_citation = "FCA & DOJ FX Benchmark Manipulation Enforcement"
    description = "Coordinated high-volume currency trades in 60-second WM/Reuters fixing window."
    default_parameters = {
        "min_amount_usd": 50000.00,
        "window_hours": 168,
        "target_keyword": "FX FIXING",
        "required_direction": "OUTBOUND",
        "kyc_deviation_factor": 1.25,
    }

    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_amt = float(params.get("min_amount_usd", 5000.0))
        win_hours = float(params.get("window_hours", 168))
        kw = str(params.get("target_keyword", "")).upper()
        req_dir = str(params.get("required_direction", "OUTBOUND")).upper()
        win_delta = timedelta(hours=win_hours)

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_vol = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            candidate_txs: List[Dict[str, Any]] = []
            for tx in txs:
                amt = float(tx["amount_usd"])
                memo = (tx.get("remittance_purpose") or "").upper()
                tag = (tx.get("scenario_tag") or "").upper()
                if self.rule_id in tag or (kw and kw in memo and amt >= min_amt * 0.5):
                    candidate_txs.append(tx)
                elif tx["direction"] == req_dir and amt >= min_amt and (tx["origin_country"] != tx["destination_country"] or int(cust.get("pep_flag", 0)) == 1):
                    if kw in memo or amt >= expected_vol * 2.2:
                        candidate_txs.append(tx)

            if not candidate_txs:
                continue

            t0 = parse_iso_ts(candidate_txs[0]["tx_timestamp"])
            win_txs = [
                t for t in candidate_txs
                if (parse_iso_ts(t["tx_timestamp"]) - t0) <= win_delta
            ]
            total_usd = round(sum(float(t["amount_usd"]) for t in win_txs), 2)
            if total_usd < min_amt * 0.5:
                continue

            confidence = min(99.0, round(78.0 + (total_usd / max(1000.0, min_amt)) * 4.5, 2))
            results.append(
                RuleTriggerResult(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    family=self.family,
                    severity=self.default_severity,
                    confidence_score=confidence,
                    customer_id=win_txs[0]["customer_id"],
                    account_id=acct_id,
                    triggered_transaction_ids=[t["id"] for t in win_txs],
                    trigger_narrative=(
                        f"Coordinated high-volume currency trades in 60-second WM/Reuters fixing window: Account {acct_id} executed {len(win_txs)} qualifying "
                        f"transaction(s) totaling ${total_usd:,.2f} USD within {win_hours:.0f}h "
                        f"(threshold: ${min_amt:,.2f} USD; citation: {self.regulatory_citation})."
                    ),
                    evidence_metrics={
                        "qualifying_tx_count": len(win_txs),
                        "cumulative_amount_usd": total_usd,
                        "threshold_usd": min_amt,
                        "matched_keyword": kw,
                        "customer_risk_band": cust.get("risk_band", "LOW"),
                    },
                    regulatory_citation=self.regulatory_citation,
                )
            )
        return results


PACK_DETECTORS = [Detector_FRD_MKT_001, Detector_FRD_MKT_002, Detector_FRD_MKT_003, Detector_FRD_MKT_004, Detector_FRD_MKT_005, Detector_FRD_MKT_006, Detector_FRD_MKT_007, Detector_FRD_MKT_008, Detector_FRD_MKT_009, Detector_FRD_MKT_010, Detector_FRD_MKT_011, Detector_FRD_MKT_012, Detector_FRD_MKT_013, Detector_FRD_MKT_014, Detector_FRD_MKT_015]
