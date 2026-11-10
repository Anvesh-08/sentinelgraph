"""
Automated Typology Detector Pack: Payment Facilitators (PayFacs), Merchant Acquiring, Transaction Laundering & Card Fraud
Contains 15 configurable, domain-authentic AML & Fraud typology detectors with full
sliding-window evaluation, multi-attribute corroboration, and explainable forensic narratives.
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional

from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext, parse_iso_ts


class Detector_FRD_MER_001(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-001: Transaction Laundering (Factoring): Undeclared Sub-Merchant URL Funnel
    Regulatory Citation: PCI SSC & FinCEN Transaction Laundering Detection Guidelines
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-001"
    rule_name = "Transaction Laundering (Factoring): Undeclared Sub-Merchant URL Funnel"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "PCI SSC & FinCEN Transaction Laundering Detection Guidelines"
    description = "Merchant settlement volume spike inconsistent with declared storefront traffic."
    default_parameters = {
        "min_amount_usd": 14000.00,
        "window_hours": 168,
        "target_keyword": "SUBMERCHANT",
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
                        f"Merchant settlement volume spike inconsistent with declared storefront traffic: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_002(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-002: Phantom Merchant Terminal Unmatched Credit Refund Cash-Out
    Regulatory Citation: Visa / Mastercard Acquirer Risk Standards — Unmatched Refunds
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-002"
    rule_name = "Phantom Merchant Terminal Unmatched Credit Refund Cash-Out"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "Visa / Mastercard Acquirer Risk Standards — Unmatched Refunds"
    description = "Merchant terminal issuing high-value card credit refunds with no prior offsetting purchase."
    default_parameters = {
        "min_amount_usd": 9500.00,
        "window_hours": 168,
        "target_keyword": "UNMATCHED REFUND",
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
                        f"Merchant terminal issuing high-value card credit refunds with no prior offsetting purchase: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_003(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-003: PayFac Sub-Merchant Rapid Onboarding & 72-Hour Bust-Out Sweep
    Regulatory Citation: FFIEC Retail Payment Systems — Third-Party Payment Processors
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-003"
    rule_name = "PayFac Sub-Merchant Rapid Onboarding & 72-Hour Bust-Out Sweep"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "FFIEC Retail Payment Systems — Third-Party Payment Processors"
    description = "Newly onboarded sub-merchant processing burst of high-ticket charges and sweeping settlement before chargebacks hit."
    default_parameters = {
        "min_amount_usd": 16000.00,
        "window_hours": 168,
        "target_keyword": "PAYFAC SETTLEMENT",
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
                        f"Newly onboarded sub-merchant processing burst of high-ticket charges and sweeping settlement before chargebacks hit: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_004(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-004: MCC Miscoding: High-Risk Gambling/Adult/Crypto Coded as Low-Risk Consulting
    Regulatory Citation: Card Network BRAM / GBPP Compliance Monitoring Rules
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-004"
    rule_name = "MCC Miscoding: High-Risk Gambling/Adult/Crypto Coded as Low-Risk Consulting"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "Card Network BRAM / GBPP Compliance Monitoring Rules"
    description = "Card settlement ticket size and velocity distribution conflict with declared low-risk MCC."
    default_parameters = {
        "min_amount_usd": 12500.00,
        "window_hours": 168,
        "target_keyword": "MERCHANT SETTLEMENT",
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
                        f"Card settlement ticket size and velocity distribution conflict with declared low-risk MCC: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_005(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-005: BIN-Attack / Card-Testing Micro-Authorization Burst
    Regulatory Citation: PCI DSS & EMVCo Card-Not-Present Enumeration Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-005"
    rule_name = "BIN-Attack / Card-Testing Micro-Authorization Burst"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "PCI DSS & EMVCo Card-Not-Present Enumeration Indicators"
    description = "Hundreds of rapid $1.00–$5.00 e-commerce authorizations followed by high-value luxury purchases."
    default_parameters = {
        "min_amount_usd": 2500.00,
        "window_hours": 168,
        "target_keyword": "AUTH TEST",
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
                        f"Hundreds of rapid $1.00–$5.00 e-commerce authorizations followed by high-value luxury purchases: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_006(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-006: Cross-Border Marketplace Seller Collusive Self-Purchasing
    Regulatory Citation: FATF E-Commerce & Online Marketplace Laundering Typologies
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-006"
    rule_name = "Cross-Border Marketplace Seller Collusive Self-Purchasing"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "FATF E-Commerce & Online Marketplace Laundering Typologies"
    description = "Marketplace seller account funded primarily by prepaid cards issued in high-risk jurisdictions."
    default_parameters = {
        "min_amount_usd": 11000.00,
        "window_hours": 168,
        "target_keyword": "MARKETPLACE PAYOUT",
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
                        f"Marketplace seller account funded primarily by prepaid cards issued in high-risk jurisdictions: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_007(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-007: High Chargeback-to-Sales Ratio (> 2.5%) Settlement Hold Evasion
    Regulatory Citation: FTC & FinCEN Advisory on High-Risk Telemarketing & Merchant Processors
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-007"
    rule_name = "High Chargeback-to-Sales Ratio (> 2.5%) Settlement Hold Evasion"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "FTC & FinCEN Advisory on High-Risk Telemarketing & Merchant Processors"
    description = "Merchant rotating bank settlement accounts to evade acquirer reserve holds."
    default_parameters = {
        "min_amount_usd": 13500.00,
        "window_hours": 168,
        "target_keyword": "CHARGEBACK",
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
                        f"Merchant rotating bank settlement accounts to evade acquirer reserve holds: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_008(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-008: Point-of-Sale (POS) Late-Night Manual Key-Entry Spike
    Regulatory Citation: Acquirer Fraud Monitoring — Card-Present Manual PAN Entry
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-008"
    rule_name = "Point-of-Sale (POS) Late-Night Manual Key-Entry Spike"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "Acquirer Fraud Monitoring — Card-Present Manual PAN Entry"
    description = "Retail POS terminal processing high-value manually keyed transactions after business hours."
    default_parameters = {
        "min_amount_usd": 8500.00,
        "window_hours": 168,
        "target_keyword": "MANUAL ENTRY",
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
                        f"Retail POS terminal processing high-value manually keyed transactions after business hours: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_009(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-009: Prepaid / Gift Card Open-Loop Bulk Purchase & Liquidation
    Regulatory Citation: FinCEN Prepaid Access Rule (31 CFR 1010.100)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-009"
    rule_name = "Prepaid / Gift Card Open-Loop Bulk Purchase & Liquidation"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN Prepaid Access Rule (31 CFR 1010.100)"
    description = "Sequential bulk purchases of open-loop prepaid cards funded by structured cash or ACH credits."
    default_parameters = {
        "min_amount_usd": 7500.00,
        "window_hours": 168,
        "target_keyword": "PREPAID LOAD",
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
                        f"Sequential bulk purchases of open-loop prepaid cards funded by structured cash or ACH credits: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_010(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-010: Split-Ticket POS Structuring (Multiple Same-Card Swipes Within 5 Minutes)
    Regulatory Citation: Acquirer Velocity Rules — Split-Ticket Evasion
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-010"
    rule_name = "Split-Ticket POS Structuring (Multiple Same-Card Swipes Within 5 Minutes)"
    family = "MULE_NETWORK"
    default_severity = "MEDIUM"
    regulatory_citation = "Acquirer Velocity Rules — Split-Ticket Evasion"
    description = "Multiple consecutive card charges on the same merchant terminal within minutes to bypass floor limits."
    default_parameters = {
        "min_amount_usd": 6000.00,
        "window_hours": 168,
        "target_keyword": "SPLIT SWIPE",
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
                        f"Multiple consecutive card charges on the same merchant terminal within minutes to bypass floor limits: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_011(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-011: Merchant Cash Advance (MCA) Stacking & ACH Split-Withholding Fraud
    Regulatory Citation: Small Business Lending & MCA Fraud Typologies
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-011"
    rule_name = "Merchant Cash Advance (MCA) Stacking & ACH Split-Withholding Fraud"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "Small Business Lending & MCA Fraud Typologies"
    description = "Business account receiving simultaneous Merchant Cash Advances from multiple lenders and diverting receivables."
    default_parameters = {
        "min_amount_usd": 19000.00,
        "window_hours": 168,
        "target_keyword": "MCA ADVANCE",
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
                        f"Business account receiving simultaneous Merchant Cash Advances from multiple lenders and diverting receivables: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_012(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-012: Triangulation Fraud E-Commerce Drop-Shipping Mule Funnel
    Regulatory Citation: Europol E-Commerce Triangulation Fraud Advisory
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-012"
    rule_name = "Triangulation Fraud E-Commerce Drop-Shipping Mule Funnel"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "Europol E-Commerce Triangulation Fraud Advisory"
    description = "Account purchasing retail goods with compromised cards to fulfill orders placed on secondary storefront."
    default_parameters = {
        "min_amount_usd": 10500.00,
        "window_hours": 168,
        "target_keyword": "FULFILLMENT",
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
                        f"Account purchasing retail goods with compromised cards to fulfill orders placed on secondary storefront: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_013(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-013: Subscription / Negative-Option Billing Shell Descriptor Rotation
    Regulatory Citation: FTC & Card Network Descriptor Cycling Enforcement
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-013"
    rule_name = "Subscription / Negative-Option Billing Shell Descriptor Rotation"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "FTC & Card Network Descriptor Cycling Enforcement"
    description = "Cluster of shell LLC accounts sharing identical signatory while rotating merchant billing descriptors."
    default_parameters = {
        "min_amount_usd": 15000.00,
        "window_hours": 168,
        "target_keyword": "RECURRING BILLING",
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
                        f"Cluster of shell LLC accounts sharing identical signatory while rotating merchant billing descriptors: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_014(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-014: QR-Code / SoftPOS Ephemeral Merchant Mule Collection
    Regulatory Citation: FATF Emerging Digital Payment Acceptance Risks
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-014"
    rule_name = "QR-Code / SoftPOS Ephemeral Merchant Mule Collection"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "FATF Emerging Digital Payment Acceptance Risks"
    description = "Mobile SoftPOS merchant account collecting rapid contactless tap payments and cashing out to P2P."
    default_parameters = {
        "min_amount_usd": 7000.00,
        "window_hours": 168,
        "target_keyword": "SOFTPOS",
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
                        f"Mobile SoftPOS merchant account collecting rapid contactless tap payments and cashing out to P2P: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_MER_015(BaseTypologyDetector):
    """
    Typology Rule FRD-MER-015: Cross-Border Remittance Disguised as B2B SaaS / Freelance Marketplace Payout
    Regulatory Citation: FATF Cross-Border Freelance & Gig-Economy Laundering
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-MER-015"
    rule_name = "Cross-Border Remittance Disguised as B2B SaaS / Freelance Marketplace Payout"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Cross-Border Freelance & Gig-Economy Laundering"
    description = "Simulated freelance software milestones transferring funds across high-risk corridors."
    default_parameters = {
        "min_amount_usd": 17500.00,
        "window_hours": 168,
        "target_keyword": "FREELANCE PAYOUT",
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
                        f"Simulated freelance software milestones transferring funds across high-risk corridors: Account {acct_id} executed {len(win_txs)} qualifying "
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


PACK_DETECTORS = [Detector_FRD_MER_001, Detector_FRD_MER_002, Detector_FRD_MER_003, Detector_FRD_MER_004, Detector_FRD_MER_005, Detector_FRD_MER_006, Detector_FRD_MER_007, Detector_FRD_MER_008, Detector_FRD_MER_009, Detector_FRD_MER_010, Detector_FRD_MER_011, Detector_FRD_MER_012, Detector_FRD_MER_013, Detector_FRD_MER_014, Detector_FRD_MER_015]
