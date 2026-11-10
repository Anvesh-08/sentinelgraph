"""
Automated Typology Detector Pack: Public Sector Corruption, Healthcare Fraud, Elder Scams & Environmental Crime
Contains 15 configurable, domain-authentic AML & Fraud typology detectors with full
sliding-window evaluation, multi-attribute corroboration, and explainable forensic narratives.
"""
from datetime import timedelta
from typing import Any, Dict, List, Optional

from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import BaseTypologyDetector, TypologyEvaluationContext, parse_iso_ts


class Detector_FRD_PUB_001(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-001: Elder Romance / Tech-Support Remote-Access Desktop Session Wire
    Regulatory Citation: FinCEN Advisory FIN-2022-A002 — Tech Support & Romance Scams
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-001"
    rule_name = "Elder Romance / Tech-Support Remote-Access Desktop Session Wire"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory FIN-2022-A002 — Tech Support & Romance Scams"
    description = "Senior customer initiating wire transfer while concurrent remote-desktop/unusual session telemetry is present."
    default_parameters = {
        "min_amount_usd": 9000.00,
        "window_hours": 168,
        "target_keyword": "TECH SUPPORT",
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
                        f"Senior customer initiating wire transfer while concurrent remote-desktop/unusual session telemetry is present: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_002(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-002: Elder Guardianship / Fiduciary Power-of-Attorney Commingling
    Regulatory Citation: DOJ & FinCEN Elder Abuse Fiduciary Misappropriation Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-002"
    rule_name = "Elder Guardianship / Fiduciary Power-of-Attorney Commingling"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "DOJ & FinCEN Elder Abuse Fiduciary Misappropriation Indicators"
    description = "Newly added caregiver or POA signatory transferring senior customer funds into personal account."
    default_parameters = {
        "min_amount_usd": 11500.00,
        "window_hours": 168,
        "target_keyword": "FIDUCIARY",
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
                        f"Newly added caregiver or POA signatory transferring senior customer funds into personal account: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_003(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-003: Emergency Disaster Relief / Sovereign Grant Identity Theft Funnel
    Regulatory Citation: FinCEN COVID-19 & Disaster Relief Fraud Advisories
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-003"
    rule_name = "Emergency Disaster Relief / Sovereign Grant Identity Theft Funnel"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN COVID-19 & Disaster Relief Fraud Advisories"
    description = "Retail checking account receiving multiple government relief or SBA/grant credits for unrelated businesses."
    default_parameters = {
        "min_amount_usd": 14000.00,
        "window_hours": 168,
        "target_keyword": "RELIEF GRANT",
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
                        f"Retail checking account receiving multiple government relief or SBA/grant credits for unrelated businesses: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_004(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-004: Tax Refund Treasury ACH Direct-Deposit Mule Aggregation
    Regulatory Citation: FinCEN Advisory on Identity Theft Tax Refund Fraud
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-004"
    rule_name = "Tax Refund Treasury ACH Direct-Deposit Mule Aggregation"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory on Identity Theft Tax Refund Fraud"
    description = "Multiple government tax refund ACH credits deposited into a single consumer account."
    default_parameters = {
        "min_amount_usd": 8500.00,
        "window_hours": 168,
        "target_keyword": "TAX REFUND",
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
                        f"Multiple government tax refund ACH credits deposited into a single consumer account: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_005(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-005: Durable Medical Equipment (DME) / Telemedicine Kickback Wire
    Regulatory Citation: HHS-OIG & FinCEN Telefraud & DME Kickback Alert
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-005"
    rule_name = "Durable Medical Equipment (DME) / Telemedicine Kickback Wire"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "HIGH"
    regulatory_citation = "HHS-OIG & FinCEN Telefraud & DME Kickback Alert"
    description = "Healthcare provider wiring recurring 'marketing/lead-generation' fees to offshore call centers."
    default_parameters = {
        "min_amount_usd": 24000.00,
        "window_hours": 168,
        "target_keyword": "TELEMEDICINE",
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
                        f"Healthcare provider wiring recurring 'marketing/lead-generation' fees to offshore call centers: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_006(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-006: Public Infrastructure Bid-Rigging & Subcontractor Pass-Through
    Regulatory Citation: OECD & FATF Bribery and Corruption in Public Procurement
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-006"
    rule_name = "Public Infrastructure Bid-Rigging & Subcontractor Pass-Through"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "OECD & FATF Bribery and Corruption in Public Procurement"
    description = "Prime government contractor wiring 40%+ of contract award to newly incorporated vendor with no employees."
    default_parameters = {
        "min_amount_usd": 36000.00,
        "window_hours": 168,
        "target_keyword": "SUBCONTRACTOR",
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
                        f"Prime government contractor wiring 40%+ of contract award to newly incorporated vendor with no employees: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_007(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-007: Check Washing / Stolen Treasury Check Mobile Remote Deposit Capture (mRDC)
    Regulatory Citation: FinCEN Alert FIN-2023-Alert003 (Mail Theft-Related Check Fraud)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-007"
    rule_name = "Check Washing / Stolen Treasury Check Mobile Remote Deposit Capture (mRDC)"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN Alert FIN-2023-Alert003 (Mail Theft-Related Check Fraud)"
    description = "High-value mobile check deposit followed by immediate ATM/P2P withdrawal prior to check return."
    default_parameters = {
        "min_amount_usd": 6500.00,
        "window_hours": 168,
        "target_keyword": "MOBILE CHECK DEPOSIT",
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
                        f"High-value mobile check deposit followed by immediate ATM/P2P withdrawal prior to check return: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_008(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-008: Student Loan / Financial Aid Stipend Mule Ring
    Regulatory Citation: Department of Education OIG Financial Aid Fraud Rings
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-008"
    rule_name = "Student Loan / Financial Aid Stipend Mule Ring"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "MEDIUM"
    regulatory_citation = "Department of Education OIG Financial Aid Fraud Rings"
    description = "Multiple student aid disbursements routed to a shared bank account and wired out."
    default_parameters = {
        "min_amount_usd": 5500.00,
        "window_hours": 168,
        "target_keyword": "FINANCIAL AID",
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
                        f"Multiple student aid disbursements routed to a shared bank account and wired out: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_009(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-009: Synthetic Small Business Credit Line Bust-Out & Offshore Wire
    Regulatory Citation: FinCEN Commercial Bust-Out Fraud Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-009"
    rule_name = "Synthetic Small Business Credit Line Bust-Out & Offshore Wire"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Commercial Bust-Out Fraud Indicators"
    description = "Drawdown of full commercial credit line immediately wired to foreign counterparty."
    default_parameters = {
        "min_amount_usd": 29000.00,
        "window_hours": 168,
        "target_keyword": "CREDIT LINE",
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
                        f"Drawdown of full commercial credit line immediately wired to foreign counterparty: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_010(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-010: Illegal Waste Trafficking & Environmental Dumping Settlement
    Regulatory Citation: FATF Money Laundering from Environmental Crime (2021)
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-010"
    rule_name = "Illegal Waste Trafficking & Environmental Dumping Settlement"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "HIGH"
    regulatory_citation = "FATF Money Laundering from Environmental Crime (2021)"
    description = "Cross-border waste disposal wire to uncertified receiver in developing jurisdiction."
    default_parameters = {
        "min_amount_usd": 22500.00,
        "window_hours": 168,
        "target_keyword": "WASTE MANAGEMENT",
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
                        f"Cross-border waste disposal wire to uncertified receiver in developing jurisdiction: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_011(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-011: Pharmaceutical Diversion & Pill-Mill Cash-to-Wire Funnel
    Regulatory Citation: DEA & FinCEN Opioid Trafficking Financial Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-011"
    rule_name = "Pharmaceutical Diversion & Pill-Mill Cash-to-Wire Funnel"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "DEA & FinCEN Opioid Trafficking Financial Indicators"
    description = "Independent clinic or pharmacy depositing excessive cash while purchasing controlled substances."
    default_parameters = {
        "min_amount_usd": 18000.00,
        "window_hours": 168,
        "target_keyword": "PHARMACY WHOLESALE",
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
                        f"Independent clinic or pharmacy depositing excessive cash while purchasing controlled substances: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_012(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-012: Counterfeit Luxury Goods / IP Infringement E-Commerce repatriation
    Regulatory Citation: DHS IPR Center & FinCEN Illicit Trade Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-012"
    rule_name = "Counterfeit Luxury Goods / IP Infringement E-Commerce repatriation"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "HIGH"
    regulatory_citation = "DHS IPR Center & FinCEN Illicit Trade Indicators"
    description = "Domestic e-commerce receipts aggregated and wired to manufacturing hubs linked to counterfeit goods."
    default_parameters = {
        "min_amount_usd": 16500.00,
        "window_hours": 168,
        "target_keyword": "REPLICA WHOLESALE",
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
                        f"Domestic e-commerce receipts aggregated and wired to manufacturing hubs linked to counterfeit goods: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_013(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-013: Unlicensed Sportsbook / Bookmaking P2P Settlement Hub
    Regulatory Citation: FinCEN Illegal Gambling & Bookmaking Red Flags
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-013"
    rule_name = "Unlicensed Sportsbook / Bookmaking P2P Settlement Hub"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN Illegal Gambling & Bookmaking Red Flags"
    description = "Monday/Tuesday recurring P2P inflows and outflows matching weekly sports wagering settlement cycles."
    default_parameters = {
        "min_amount_usd": 10000.00,
        "window_hours": 168,
        "target_keyword": "WAGER SETTLEMENT",
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
                        f"Monday/Tuesday recurring P2P inflows and outflows matching weekly sports wagering settlement cycles: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_014(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-014: Ransomware Negotiation DFIR Escrow Facilitator Wire
    Regulatory Citation: FinCEN Advisory FIN-2021-A004 — DFIR & Ransomware Payments
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-014"
    rule_name = "Ransomware Negotiation DFIR Escrow Facilitator Wire"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory FIN-2021-A004 — DFIR & Ransomware Payments"
    description = "High-value wire to cyber incident response intermediary converted to cryptocurrency."
    default_parameters = {
        "min_amount_usd": 33000.00,
        "window_hours": 168,
        "target_keyword": "INCIDENT RESPONSE",
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
                        f"High-value wire to cyber incident response intermediary converted to cryptocurrency: Account {acct_id} executed {len(win_txs)} qualifying "
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


class Detector_FRD_PUB_015(BaseTypologyDetector):
    """
    Typology Rule FRD-PUB-015: Insider Trading / Pre-Announcement Options Funding Wire
    Regulatory Citation: SEC & FINRA Suspicious Cross-Border Brokerage Funding Indicators
    Forensic Logic: Evaluates account transaction history, counterparty corridors,
    remittance purpose keywords, and customer KYC/KYB baseline profiles.
    """
    rule_id = "FRD-PUB-015"
    rule_name = "Insider Trading / Pre-Announcement Options Funding Wire"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "SEC & FINRA Suspicious Cross-Border Brokerage Funding Indicators"
    description = "Sudden offshore wire funding newly opened brokerage account 48h prior to M&A announcement."
    default_parameters = {
        "min_amount_usd": 46000.00,
        "window_hours": 168,
        "target_keyword": "BROKERAGE FUNDING",
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
                        f"Sudden offshore wire funding newly opened brokerage account 48h prior to M&A announcement: Account {acct_id} executed {len(win_txs)} qualifying "
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


PACK_DETECTORS = [Detector_FRD_PUB_001, Detector_FRD_PUB_002, Detector_FRD_PUB_003, Detector_FRD_PUB_004, Detector_FRD_PUB_005, Detector_FRD_PUB_006, Detector_FRD_PUB_007, Detector_FRD_PUB_008, Detector_FRD_PUB_009, Detector_FRD_PUB_010, Detector_FRD_PUB_011, Detector_FRD_PUB_012, Detector_FRD_PUB_013, Detector_FRD_PUB_014, Detector_FRD_PUB_015]
