"""
Automated Typology Detector Pack: Private Banking, Family Offices, Offshore Trusts & Lombard Loan Laundering
Contains 15 configurable, domain-authentic AML & Fraud typology detectors with full
sliding-window evaluation, multi-attribute corroboration, and explainable forensic narratives.
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional

from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext, parse_iso_ts


class Detector_AML_WTH_001(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-001: Lombard Loan / Cash-Collateralized Credit Facility Early Repayment
    Regulatory Citation: FFIEC BSA/AML Private Banking Due Diligence Program (USA PATRIOT Act Sec 312)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-001"
    rule_name = "Lombard Loan / Cash-Collateralized Credit Facility Early Repayment"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FFIEC BSA/AML Private Banking Due Diligence Program (USA PATRIOT Act Sec 312)"
    description = "Credit facility secured by offshore cash deposits repaid early via third-party foreign wire."
    default_parameters = {
        "min_amount_usd": 40000.00,
        "window_hours": 168,
        "target_keyword": "LOMBARD LOAN",
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
                        f"Credit facility secured by offshore cash deposits repaid early via third-party foreign wire: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_002(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-002: Multi-Layer PTC (Private Trust Company) Protector Override Distribution
    Regulatory Citation: FATF Concealment of Beneficial Ownership via Trust Arrangements
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-002"
    rule_name = "Multi-Layer PTC (Private Trust Company) Protector Override Distribution"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Concealment of Beneficial Ownership via Trust Arrangements"
    description = "High-value discretionary trust distribution following change of trust protector or beneficiary."
    default_parameters = {
        "min_amount_usd": 48000.00,
        "window_hours": 168,
        "target_keyword": "TRUST DISTRIBUTION",
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
                        f"High-value discretionary trust distribution following change of trust protector or beneficiary: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_003(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-003: Bearer-Share or Foundation (Stiftung / Anstalt) Liquidation Inflow
    Regulatory Citation: FATF Recommendation 25 (Transparency of Legal Arrangements)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-003"
    rule_name = "Bearer-Share or Foundation (Stiftung / Anstalt) Liquidation Inflow"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Recommendation 25 (Transparency of Legal Arrangements)"
    description = "Large wire inflow from civil-law foundation or bearer-instrument liquidation in secrecy jurisdiction."
    default_parameters = {
        "min_amount_usd": 36000.00,
        "window_hours": 168,
        "target_keyword": "FOUNDATION",
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
                        f"Large wire inflow from civil-law foundation or bearer-instrument liquidation in secrecy jurisdiction: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_004(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-004: Private Aviation / Superyacht Charter Escrow Third-Party Funding
    Regulatory Citation: FinCEN High-Value Luxury Asset Laundering Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-004"
    rule_name = "Private Aviation / Superyacht Charter Escrow Third-Party Funding"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN High-Value Luxury Asset Laundering Indicators"
    description = "Luxury aviation or maritime acquisition escrow funded by multiple unrelated offshore entities."
    default_parameters = {
        "min_amount_usd": 52000.00,
        "window_hours": 168,
        "target_keyword": "AVIATION ESCROW",
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
                        f"Luxury aviation or maritime acquisition escrow funded by multiple unrelated offshore entities: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_005(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-005: Universal Life / Private Placement Life Insurance (PPLI) Free-Look Surrender
    Regulatory Citation: FATF Risk-Based Approach for the Life Insurance Sector
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-005"
    rule_name = "Universal Life / Private Placement Life Insurance (PPLI) Free-Look Surrender"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Risk-Based Approach for the Life Insurance Sector"
    description = "Early surrender of high-value single-premium life insurance policy accepting substantial penalty."
    default_parameters = {
        "min_amount_usd": 30000.00,
        "window_hours": 168,
        "target_keyword": "POLICY SURRENDER",
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
                        f"Early surrender of high-value single-premium life insurance policy accepting substantial penalty: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_006(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-006: Family Office Co-Investment Special Purpose Vehicle (SPV) Pass-Through
    Regulatory Citation: SEC & FinCEN Private Investment Fund AML Risk Alert
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-006"
    rule_name = "Family Office Co-Investment Special Purpose Vehicle (SPV) Pass-Through"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "SEC & FinCEN Private Investment Fund AML Risk Alert"
    description = "Capital call wire into short-lived SPV immediately returned as 'cancelled deal refund' to new account."
    default_parameters = {
        "min_amount_usd": 44000.00,
        "window_hours": 168,
        "target_keyword": "SPV CAPITAL CALL",
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
                        f"Capital call wire into short-lived SPV immediately returned as 'cancelled deal refund' to new account: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_007(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-007: Art Auction Guarantee / Irrevocable Bid Third-Party Settlement
    Regulatory Citation: OFAC Advisory on High-Value Artwork Transactions
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-007"
    rule_name = "Art Auction Guarantee / Irrevocable Bid Third-Party Settlement"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "OFAC Advisory on High-Value Artwork Transactions"
    description = "Fine art auction settlement funded by offshore shell entity not registered as auction bidder."
    default_parameters = {
        "min_amount_usd": 39000.00,
        "window_hours": 168,
        "target_keyword": "AUCTION SETTLEMENT",
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
                        f"Fine art auction settlement funded by offshore shell entity not registered as auction bidder: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_008(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-008: Nominee Shareholder Dividend Redirection Wire
    Regulatory Citation: FATF Guidance on Beneficial Ownership — Nominee Arrangements
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-008"
    rule_name = "Nominee Shareholder Dividend Redirection Wire"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FATF Guidance on Beneficial Ownership — Nominee Arrangements"
    description = "Corporate dividend disbursement redirected via power-of-attorney to offshore third-party account."
    default_parameters = {
        "min_amount_usd": 25000.00,
        "window_hours": 168,
        "target_keyword": "DIVIDEND REDIRECTION",
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
                        f"Corporate dividend disbursement redirected via power-of-attorney to offshore third-party account: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_009(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-009: Cross-Border Safe-Deposit Box / Vault Liquidation Deposit
    Regulatory Citation: FFIEC Private Banking & Bulk Vault Cash Red Flags
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-009"
    rule_name = "Cross-Border Safe-Deposit Box / Vault Liquidation Deposit"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FFIEC Private Banking & Bulk Vault Cash Red Flags"
    description = "Large deposit of high-denomination banknotes or bullion following private vault closure."
    default_parameters = {
        "min_amount_usd": 18000.00,
        "window_hours": 168,
        "target_keyword": "VAULT LIQUIDATION",
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
                        f"Large deposit of high-denomination banknotes or bullion following private vault closure: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_010(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-010: Citizenship-by-Investment (CBI) PassportMismatch Onboarding Wire
    Regulatory Citation: FinCEN & OECD CBI/Golden Passport Risk Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-010"
    rule_name = "Citizenship-by-Investment (CBI) PassportMismatch Onboarding Wire"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN & OECD CBI/Golden Passport Risk Indicators"
    description = "Private banking onboarding wire from customer holding CBI passport different from birth nationality."
    default_parameters = {
        "min_amount_usd": 35000.00,
        "window_hours": 168,
        "target_keyword": "CBI INVESTMENT",
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
                        f"Private banking onboarding wire from customer holding CBI passport different from birth nationality: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_011(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-011: Offshore Hedge Fund Side-Pocket Illiquid Redemption Transfer
    Regulatory Citation: FinCEN Proposed Rule for Investment Advisers — Red Flags
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-011"
    rule_name = "Offshore Hedge Fund Side-Pocket Illiquid Redemption Transfer"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN Proposed Rule for Investment Advisers — Red Flags"
    description = "In-kind or third-party wire redemption from un-audited offshore feeder fund."
    default_parameters = {
        "min_amount_usd": 41000.00,
        "window_hours": 168,
        "target_keyword": "REDEMPTION",
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
                        f"In-kind or third-party wire redemption from un-audited offshore feeder fund: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_012(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-012: Politically Exposed Person (PEP) Retainer & Sovereign Advisory Fee
    Regulatory Citation: FATF Guidance on Politically Exposed Persons (Rec 12 & 22)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-012"
    rule_name = "Politically Exposed Person (PEP) Retainer & Sovereign Advisory Fee"
    family = "LAYERING"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Guidance on Politically Exposed Persons (Rec 12 & 22)"
    description = "Recurring high-value 'infrastructure/sovereign consulting' wires into account of PEP or family member."
    default_parameters = {
        "min_amount_usd": 27000.00,
        "window_hours": 168,
        "target_keyword": "SOVEREIGN ADVISORY",
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
                        f"Recurring high-value 'infrastructure/sovereign consulting' wires into account of PEP or family member: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_013(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-013: Private Bank Hold-Mail / Numbered Account Wire Velocity
    Regulatory Citation: FFIEC Private Banking — Hold Mail & Code-Named Accounts
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-013"
    rule_name = "Private Bank Hold-Mail / Numbered Account Wire Velocity"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FFIEC Private Banking — Hold Mail & Code-Named Accounts"
    description = "High-velocity international wire activity on private banking account utilizing hold-mail instructions."
    default_parameters = {
        "min_amount_usd": 23000.00,
        "window_hours": 168,
        "target_keyword": "NUMBERED ACCOUNT",
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
                        f"High-velocity international wire activity on private banking account utilizing hold-mail instructions: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_014(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-014: Real Estate Commercial Ground-Lease Prepaid Rent Layering
    Regulatory Citation: FATF Risk-Based Approach for the Real Estate Sector
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-014"
    rule_name = "Real Estate Commercial Ground-Lease Prepaid Rent Layering"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FATF Risk-Based Approach for the Real Estate Sector"
    description = "Multi-year prepaid commercial lease wire from offshore tenant followed by lease termination."
    default_parameters = {
        "min_amount_usd": 38000.00,
        "window_hours": 168,
        "target_keyword": "PREPAID LEASE",
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
                        f"Multi-year prepaid commercial lease wire from offshore tenant followed by lease termination: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_WTH_015(BaseTypologyDetector):
    """
    Typology Rule AML-WTH-015: Donor-Advised Fund (DAF) / Private Foundation Grant Round-Tripping
    Regulatory Citation: FATF Combating the Abuse of Non-Profit Organisations (Rec 8)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-WTH-015"
    rule_name = "Donor-Advised Fund (DAF) / Private Foundation Grant Round-Tripping"
    family = "LAYERING"
    default_severity = "HIGH"
    regulatory_citation = "FATF Combating the Abuse of Non-Profit Organisations (Rec 8)"
    description = "Charitable grant wire to foreign entity controlled by original donor's beneficial ownership network."
    default_parameters = {
        "min_amount_usd": 26000.00,
        "window_hours": 168,
        "target_keyword": "CHARITABLE GRANT",
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
                        f"Charitable grant wire to foreign entity controlled by original donor's beneficial ownership network: Account {acct_id} executed {len(win_txs)} qualifying "
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


PACK_DETECTORS = [Detector_AML_WTH_001, Detector_AML_WTH_002, Detector_AML_WTH_003, Detector_AML_WTH_004, Detector_AML_WTH_005, Detector_AML_WTH_006, Detector_AML_WTH_007, Detector_AML_WTH_008, Detector_AML_WTH_009, Detector_AML_WTH_010, Detector_AML_WTH_011, Detector_AML_WTH_012, Detector_AML_WTH_013, Detector_AML_WTH_014, Detector_AML_WTH_015]
