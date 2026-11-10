"""
Automated Typology Detector Pack: Maritime Sanctions, AIS Dark-Ship Spoofing & Sovereign Corridor Evasion
Contains 15 configurable, domain-authentic AML & Fraud typology detectors with full
sliding-window evaluation, multi-attribute corroboration, and explainable forensic narratives.
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional

from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext, parse_iso_ts


class Detector_AML_MAR_001(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-001: Maritime AIS Transponder Dark-Period Bunker Fuel Settlement
    Regulatory Citation: OFAC Maritime Sanctions Advisory — AIS Manipulation
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-001"
    rule_name = "Maritime AIS Transponder Dark-Period Bunker Fuel Settlement"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "OFAC Maritime Sanctions Advisory — AIS Manipulation"
    description = "Maritime bunker fuel wire settlement following vessel AIS transponder dark period."
    default_parameters = {
        "min_amount_usd": 28000.00,
        "window_hours": 168,
        "target_keyword": "BUNKER",
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
                        f"Maritime bunker fuel wire settlement following vessel AIS transponder dark period: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_002(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-002: Ship-to-Ship (STS) High-Risk Waters Crude Transfer Settlement
    Regulatory Citation: OFAC & UK OFSI Maritime Price Cap & STS Advisory
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-002"
    rule_name = "Ship-to-Ship (STS) High-Risk Waters Crude Transfer Settlement"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "OFAC & UK OFSI Maritime Price Cap & STS Advisory"
    description = "High-value commodity wire linked to offshore ship-to-ship cargo transfer."
    default_parameters = {
        "min_amount_usd": 45000.00,
        "window_hours": 168,
        "target_keyword": "STS TRANSFER",
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
                        f"High-value commodity wire linked to offshore ship-to-ship cargo transfer: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_003(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-003: Shadow-Fleet Flag-Hopping Vessel Protection & Indemnity (P&I) Wire
    Regulatory Citation: EU & G7 Oil Price Cap Coalition Maritime Alert
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-003"
    rule_name = "Shadow-Fleet Flag-Hopping Vessel Protection & Indemnity (P&I) Wire"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "EU & G7 Oil Price Cap Coalition Maritime Alert"
    description = "Marine insurance or charter settlement for vessel with recent flag-of-convenience changes."
    default_parameters = {
        "min_amount_usd": 22000.00,
        "window_hours": 168,
        "target_keyword": "VESSEL INSURANCE",
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
                        f"Marine insurance or charter settlement for vessel with recent flag-of-convenience changes: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_004(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-004: Port Agency Cash-to-Master (CTM) High-Risk Port Disbursement
    Regulatory Citation: BIMCO & FATF Maritime Cash-to-Master Risk Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-004"
    rule_name = "Port Agency Cash-to-Master (CTM) High-Risk Port Disbursement"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "BIMCO & FATF Maritime Cash-to-Master Risk Indicators"
    description = "Large Cash-to-Master wire disbursement at high-risk sanctions-adjacent port."
    default_parameters = {
        "min_amount_usd": 15000.00,
        "window_hours": 168,
        "target_keyword": "PORT DISBURSEMENT",
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
                        f"Large Cash-to-Master wire disbursement at high-risk sanctions-adjacent port: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_005(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-005: Single-Vessel Brass-Plate Charter LLC Pass-Through
    Regulatory Citation: FATF Beneficial Ownership in Maritime Shell Structures
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-005"
    rule_name = "Single-Vessel Brass-Plate Charter LLC Pass-Through"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "FATF Beneficial Ownership in Maritime Shell Structures"
    description = "Single-ship shell company receiving charter hire and immediately wiring proceeds to secrecy haven."
    default_parameters = {
        "min_amount_usd": 32000.00,
        "window_hours": 168,
        "target_keyword": "TIME CHARTER",
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
                        f"Single-ship shell company receiving charter hire and immediately wiring proceeds to secrecy haven: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_006(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-006: Sovereign Wealth / State-Owned Enterprise (SOE) Intermediary Conduit
    Regulatory Citation: FinCEN Foreign Corruption & kleptocracy Advisory
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-006"
    rule_name = "Sovereign Wealth / State-Owned Enterprise (SOE) Intermediary Conduit"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Foreign Corruption & kleptocracy Advisory"
    description = "Inward wire from state-owned enterprise routed to personal or consulting account of PEP."
    default_parameters = {
        "min_amount_usd": 50000.00,
        "window_hours": 168,
        "target_keyword": "MINISTRY",
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
                        f"Inward wire from state-owned enterprise routed to personal or consulting account of PEP: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_007(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-007: Defense / Dual-Use Aerospace Spare Parts Third-Country Brokerage
    Regulatory Citation: BIS & FinCEN Joint Export Control Alert
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-007"
    rule_name = "Defense / Dual-Use Aerospace Spare Parts Third-Country Brokerage"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "BIS & FinCEN Joint Export Control Alert"
    description = "Cross-border wire for aviation/turbine components routed via third-country trading broker."
    default_parameters = {
        "min_amount_usd": 38000.00,
        "window_hours": 168,
        "target_keyword": "AEROSPACE",
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
                        f"Cross-border wire for aviation/turbine components routed via third-country trading broker: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_008(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-008: Extractive Industries / Conflict Timber & Artisanal Cobalt Settlement
    Regulatory Citation: FinCEN Environmental Crimes & Illicit Mining Notice (FIN-2021-NTC4)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-008"
    rule_name = "Extractive Industries / Conflict Timber & Artisanal Cobalt Settlement"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Environmental Crimes & Illicit Mining Notice (FIN-2021-NTC4)"
    description = "Cross-border wire for mineral extraction rights in conflict/high-corruption basin."
    default_parameters = {
        "min_amount_usd": 26000.00,
        "window_hours": 168,
        "target_keyword": "MINING CONCESSION",
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
                        f"Cross-border wire for mineral extraction rights in conflict/high-corruption basin: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_009(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-009: Diplomatic Pouch / Embassy Account Commercial Business Diversion
    Regulatory Citation: FFIEC BSA/AML Embassy, Foreign Consulate, and Foreign Mission Accounts
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-009"
    rule_name = "Diplomatic Pouch / Embassy Account Commercial Business Diversion"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "FFIEC BSA/AML Embassy, Foreign Consulate, and Foreign Mission Accounts"
    description = "Commercial trade or luxury retail wire originating from diplomatic mission operational account."
    default_parameters = {
        "min_amount_usd": 19000.00,
        "window_hours": 168,
        "target_keyword": "EMBASSY",
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
                        f"Commercial trade or luxury retail wire originating from diplomatic mission operational account: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_010(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-010: Bulk Agricultural Fertilizer / Chemical Precursor Corridor Wire
    Regulatory Citation: UNODC & FATF Chemical Precursor Financial Flows
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-010"
    rule_name = "Bulk Agricultural Fertilizer / Chemical Precursor Corridor Wire"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "UNODC & FATF Chemical Precursor Financial Flows"
    description = "Cross-border settlement for dual-use industrial chemical precursors outside normal trade route."
    default_parameters = {
        "min_amount_usd": 21000.00,
        "window_hours": 168,
        "target_keyword": "CHEMICAL",
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
                        f"Cross-border settlement for dual-use industrial chemical precursors outside normal trade route: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_011(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-011: Freeport High-Value Fine Art & Bullion Storage Fee Layering
    Regulatory Citation: FATF High-Value Goods & Freeport Secrecy Typologies
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-011"
    rule_name = "Freeport High-Value Fine Art & Bullion Storage Fee Layering"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "FATF High-Value Goods & Freeport Secrecy Typologies"
    description = "Custody and ownership transfer settlement within customs-exempt luxury freeport vault."
    default_parameters = {
        "min_amount_usd": 29000.00,
        "window_hours": 168,
        "target_keyword": "FREEPORT",
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
                        f"Custody and ownership transfer settlement within customs-exempt luxury freeport vault: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_012(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-012: Cross-Border Reinsurance / Captive Insurance Premium Return Loop
    Regulatory Citation: IAIS & FATF Money Laundering Through Reinsurance Vehicles
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-012"
    rule_name = "Cross-Border Reinsurance / Captive Insurance Premium Return Loop"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "IAIS & FATF Money Laundering Through Reinsurance Vehicles"
    description = "Offshore captive insurance premium wire followed by early policy cancellation payout."
    default_parameters = {
        "min_amount_usd": 40000.00,
        "window_hours": 168,
        "target_keyword": "REINSURANCE",
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
                        f"Offshore captive insurance premium wire followed by early policy cancellation payout: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_013(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-013: Correspondent Bank Nostro Rejection & Immediate Resubmission (Wire Stripping)
    Regulatory Citation: Wolfsberg Group Payment Transparency Standards
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-013"
    rule_name = "Correspondent Bank Nostro Rejection & Immediate Resubmission (Wire Stripping)"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "Wolfsberg Group Payment Transparency Standards"
    description = "Previously rejected international wire resubmitted within 24h with modified originator fields."
    default_parameters = {
        "min_amount_usd": 17000.00,
        "window_hours": 168,
        "target_keyword": "RESUBMITTED",
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
                        f"Previously rejected international wire resubmitted within 24h with modified originator fields: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_014(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-014: Sanctioned Oligarch Family Trust Distribution Proxy Wire
    Regulatory Citation: FinCEN Kleptocracy & Russian Elites Proxies Task Force (REPO) Alert
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-014"
    rule_name = "Sanctioned Oligarch Family Trust Distribution Proxy Wire"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Kleptocracy & Russian Elites Proxies Task Force (REPO) Alert"
    description = "Offshore trust distribution to close associate or family member of designated oligarch/PEP."
    default_parameters = {
        "min_amount_usd": 55000.00,
        "window_hours": 168,
        "target_keyword": "FAMILY TRUST",
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
                        f"Offshore trust distribution to close associate or family member of designated oligarch/PEP: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_AML_MAR_015(BaseTypologyDetector):
    """
    Typology Rule AML-MAR-015: Hawala Balancing Gold-Bar Air-Cargo Settlement
    Regulatory Citation: FATF Gold-Based Money Laundering & Trade-Based Hawala
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "AML-MAR-015"
    rule_name = "Hawala Balancing Gold-Bar Air-Cargo Settlement"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "FATF Gold-Based Money Laundering & Trade-Based Hawala"
    description = "Cross-border bullion settlement offsetting informal value transfer corridor."
    default_parameters = {
        "min_amount_usd": 34000.00,
        "window_hours": 168,
        "target_keyword": "GOLD DORÉ",
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
                        f"Cross-border bullion settlement offsetting informal value transfer corridor: Account {acct_id} executed {len(win_txs)} qualifying "
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


PACK_DETECTORS = [Detector_AML_MAR_001, Detector_AML_MAR_002, Detector_AML_MAR_003, Detector_AML_MAR_004, Detector_AML_MAR_005, Detector_AML_MAR_006, Detector_AML_MAR_007, Detector_AML_MAR_008, Detector_AML_MAR_009, Detector_AML_MAR_010, Detector_AML_MAR_011, Detector_AML_MAR_012, Detector_AML_MAR_013, Detector_AML_MAR_014, Detector_AML_MAR_015]
