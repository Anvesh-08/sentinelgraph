"""
Concrete implementations of:
- Family C (Mule Networks, Fan-In / Fan-Out & Graph Anomalies: AML-NET-001..005)
- Family D (Geographic, Corridor & Sanctions Evasion: AML-GEO-001..005)
- Family E (Behavioral Anomalies, ATO & Commercial Fraud: FRD-BEH-001..005)
"""
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from backend.app.core.models_constants import (
    FATF_BLACK_LIST_COUNTRIES,
    FATF_GREY_LIST_COUNTRIES,
    OFFSHORE_FINANCIAL_CENTERS,
)
from backend.app.models.domain import RuleTriggerResult
from backend.app.typologies.base import (
    BaseTypologyDetector,
    TypologyEvaluationContext,
    haversine_km,
    parse_iso_ts,
)


# ==============================================================================
# FAMILY C — MULE NETWORKS, FAN-IN / FAN-OUT & GRAPH ANOMALIES
# ==============================================================================

class FanInCollectorHubDetector(BaseTypologyDetector):
    rule_id = "AML-NET-001"
    rule_name = "Fan-In Collector Hub (Many-to-One Mule Aggregation)"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Financial Trend Analysis — Money Mule Collector Hubs"
    default_parameters = {
        "min_distinct_senders": 4,
        "min_total_inbound_usd": 12000.0,
        "window_hours": 72,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_senders = int(params["min_distinct_senders"])
        min_total = float(params["min_total_inbound_usd"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for target_acct, in_txs in context.inbound_by_target_account.items():
            if len(in_txs) < min_senders:
                continue
            for i, start_tx in enumerate(in_txs):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in in_txs[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                senders: Set[str] = set()
                for t in win:
                    if t["account_id"] != target_acct:
                        senders.add(t["account_id"])
                    elif t.get("counterparty_id"):
                        senders.add(t["counterparty_id"])
                    elif t.get("counterparty_account_id"):
                        senders.add(t["counterparty_account_id"])
                total_in = round(sum(float(t["amount_usd"]) for t in win), 2)
                if len(senders) >= min_senders and total_in >= min_total:
                    cust_id = context.accounts_by_id.get(target_acct, {}).get("customer_id", start_tx["customer_id"])
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=94.0,
                            customer_id=cust_id,
                            account_id=target_acct,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Fan-In collector hub behavior: Account aggregated ${total_in:,.2f} from "
                                f"{len(senders)} distinct senders within {params['window_hours']} hours."
                            ),
                            evidence_metrics={
                                "distinct_sender_count": len(senders),
                                "total_inbound_usd": total_in,
                                "window_hours": params["window_hours"],
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class FanOutDistributorHubDetector(BaseTypologyDetector):
    rule_id = "AML-NET-002"
    rule_name = "Fan-Out Distributor Hub (One-to-Many Smurf Dispersion)"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "Europol / FATF Money Mule Typology — Rapid One-to-Many Dispersion"
    default_parameters = {
        "min_distinct_recipients": 4,
        "min_total_outbound_usd": 12000.0,
        "window_hours": 72,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_recip = int(params["min_distinct_recipients"])
        min_total = float(params["min_total_outbound_usd"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            out_txs = [t for t in txs if t["direction"] == "OUTBOUND"]
            if len(out_txs) < min_recip:
                continue
            for i, start_tx in enumerate(out_txs):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in out_txs[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                recipients = {
                    t.get("counterparty_account_id") or t.get("counterparty_id") or f"ext-{t['id']}"
                    for t in win
                }
                total_out = round(sum(float(t["amount_usd"]) for t in win), 2)
                if len(recipients) >= min_recip and total_out >= min_total:
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=90.0,
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Fan-Out dispersion hub behavior: Account distributed ${total_out:,.2f} outbound "
                                f"to {len(recipients)} distinct recipients within {params['window_hours']} hours."
                            ),
                            evidence_metrics={
                                "distinct_recipient_count": len(recipients),
                                "total_outbound_usd": total_out,
                                "window_hours": params["window_hours"],
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class SharedDeviceOrIpRingDetector(BaseTypologyDetector):
    rule_id = "AML-NET-003"
    rule_name = "Shared Device Fingerprint or IP Address Across Unrelated Customers"
    family = "MULE_NETWORK"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory FIN-2022-A002"
    default_parameters = {
        "min_shared_accounts": 2,
        "min_combined_tx_usd": 5000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_accts = int(params["min_shared_accounts"])
        min_usd = float(params["min_combined_tx_usd"])

        results: List[RuleTriggerResult] = []
        reported_accounts: Set[str] = set()

        for dev_fp, acct_set in context.accounts_by_device.items():
            if len(acct_set) < min_accts:
                continue
            cust_ids = {
                context.accounts_by_id.get(a, {}).get("customer_id")
                for a in acct_set
                if context.accounts_by_id.get(a)
            }
            if len(cust_ids) < min_accts:
                continue

            ring_txs = [
                t for t in context.all_transactions
                if t.get("device_fingerprint") == dev_fp
            ]
            total_ring_usd = round(sum(float(t["amount_usd"]) for t in ring_txs), 2)
            if total_ring_usd < min_usd:
                continue

            for acct_id in sorted(acct_set):
                if acct_id in reported_accounts:
                    continue
                reported_accounts.add(acct_id)
                acct_txs = [t for t in ring_txs if t["account_id"] == acct_id] or ring_txs
                cust_id = context.accounts_by_id.get(acct_id, {}).get("customer_id", acct_txs[0]["customer_id"])
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=96.0,
                        customer_id=cust_id,
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in acct_txs],
                        trigger_narrative=(
                            f"Coordinated cyber/mule ring indicator: Hardware device fingerprint '{dev_fp}' "
                            f"is shared across {len(cust_ids)} unrelated customers ({', '.join(sorted(acct_set))}) "
                            f"with ${total_ring_usd:,.2f} in combined transaction volume."
                        ),
                        evidence_metrics={
                            "shared_device_fingerprint": dev_fp,
                            "linked_accounts": sorted(acct_set),
                            "linked_customer_count": len(cust_ids),
                            "combined_ring_volume_usd": total_ring_usd,
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


class HighRiskContagionTransferDetector(BaseTypologyDetector):
    rule_id = "AML-NET-004"
    rule_name = "Direct Contagion Transfer with High-Risk / Restricted Entity"
    family = "MULE_NETWORK"
    default_severity = "HIGH"
    regulatory_citation = "31 CFR 1020.210"
    default_parameters = {
        "min_transfer_usd": 2000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_usd = float(params["min_transfer_usd"])

        high_risk_accounts: Set[str] = set(context.flagged_account_ids)
        for acct_id, acct in context.accounts_by_id.items():
            if acct.get("status") in ("FROZEN", "RESTRICTED"):
                high_risk_accounts.add(acct_id)
            cust = context.customers_by_id.get(acct["customer_id"], {})
            if (
                cust.get("risk_band") == "CRITICAL"
                or cust.get("sanctions_status") != "CLEAR"
                or int(cust.get("pep_flag", 0)) == 1
            ):
                high_risk_accounts.add(acct_id)

        results: List[RuleTriggerResult] = []
        seen = set()
        for tx in context.all_transactions:
            peer_acct = tx.get("counterparty_account_id")
            if not peer_acct or float(tx["amount_usd"]) < min_usd:
                continue
            if peer_acct in high_risk_accounts and tx["account_id"] not in seen:
                seen.add(tx["account_id"])
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=85.0,
                        customer_id=tx["customer_id"],
                        account_id=tx["account_id"],
                        triggered_transaction_ids=[tx["id"]],
                        trigger_narrative=(
                            f"Direct network contagion: Account transferred ${float(tx['amount_usd']):,.2f} "
                            f"with high-risk/restricted internal counterparty account '{peer_acct}'."
                        ),
                        evidence_metrics={
                            "counterparty_account_id": peer_acct,
                            "amount_usd": float(tx["amount_usd"]),
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


class ReciprocalWashTransferDetector(BaseTypologyDetector):
    rule_id = "AML-NET-005"
    rule_name = "Reciprocal Back-and-Forth Wash Transfers Without Economic Purpose"
    family = "MULE_NETWORK"
    default_severity = "MEDIUM"
    regulatory_citation = "FATF Indicators of Wash Trading & Sham Commercial Invoicing"
    default_parameters = {
        "min_round_trips": 2,
        "min_total_wash_usd": 8000.0,
        "window_hours": 168,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_trips = int(params["min_round_trips"])
        min_wash = float(params["min_total_wash_usd"])

        pair_txs: Dict[tuple, List[Dict[str, Any]]] = {}
        for tx in context.all_transactions:
            peer = tx.get("counterparty_account_id")
            if not peer or tx["direction"] != "OUTBOUND":
                continue
            pair_key = tuple(sorted([tx["account_id"], peer]))
            pair_txs.setdefault(pair_key, []).append(tx)

        results: List[RuleTriggerResult] = []
        for (acct_1, acct_2), txs in pair_txs.items():
            a_to_b = [t for t in txs if t["account_id"] == acct_1]
            b_to_a = [t for t in txs if t["account_id"] == acct_2]
            if len(a_to_b) >= min_trips and len(b_to_a) >= min_trips:
                total_wash = round(sum(float(t["amount_usd"]) for t in txs), 2)
                if total_wash >= min_wash:
                    cust_id = context.accounts_by_id.get(acct_1, {}).get("customer_id", txs[0]["customer_id"])
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=84.0,
                            customer_id=cust_id,
                            account_id=acct_1,
                            triggered_transaction_ids=[t["id"] for t in txs],
                            trigger_narrative=(
                                f"Reciprocal wash transfers detected between accounts {acct_1} and {acct_2}: "
                                f"{len(a_to_b)} outbound and {len(b_to_a)} return transfers totaling ${total_wash:,.2f}."
                            ),
                            evidence_metrics={
                                "account_a": acct_1,
                                "account_b": acct_2,
                                "a_to_b_count": len(a_to_b),
                                "b_to_a_count": len(b_to_a),
                                "total_wash_volume_usd": total_wash,
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
        return results


# ==============================================================================
# FAMILY D — GEOGRAPHIC, CORRIDOR & SANCTIONS EVASION (AML-GEO-001 .. 005)
# ==============================================================================

class HighRiskJurisdictionWireDetector(BaseTypologyDetector):
    rule_id = "AML-GEO-001"
    rule_name = "FATF Black-List or High-Risk Grey-List Jurisdiction Wire Transfer"
    family = "GEOGRAPHIC"
    default_severity = "CRITICAL"
    regulatory_citation = "31 CFR 1010.610 / FATF High-Risk Jurisdictions"
    default_parameters = {
        "min_high_risk_wire_usd": 3000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_usd = float(params["min_high_risk_wire_usd"])
        monitored = FATF_BLACK_LIST_COUNTRIES | FATF_GREY_LIST_COUNTRIES

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            flagged = [
                t for t in txs
                if float(t["amount_usd"]) >= min_usd
                and (t["origin_country"] in monitored or t["destination_country"] in monitored)
            ]
            if flagged:
                total_usd = round(sum(float(t["amount_usd"]) for t in flagged), 2)
                countries = sorted(
                    ({t["origin_country"] for t in flagged} | {t["destination_country"] for t in flagged})
                    & monitored
                )
                is_black = bool(set(countries) & FATF_BLACK_LIST_COUNTRIES)
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity="CRITICAL" if is_black else "HIGH",
                        confidence_score=98.0 if is_black else 88.0,
                        customer_id=flagged[0]["customer_id"],
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in flagged],
                        trigger_narrative=(
                            f"Account executed {len(flagged)} transfer(s) totaling ${total_usd:,.2f} involving "
                            f"FATF high-risk/monitored jurisdiction(s): {', '.join(countries)}."
                        ),
                        evidence_metrics={
                            "high_risk_countries": countries,
                            "tx_count": len(flagged),
                            "total_high_risk_usd": total_usd,
                            "includes_fatf_blacklist": is_black,
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


class OffshoreTaxHavenLayeringDetector(BaseTypologyDetector):
    rule_id = "AML-GEO-002"
    rule_name = "Offshore Secrecy Haven Shell-Company Wire Layering"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN CDD Rule & Offshore Shell Company Typologies"
    default_parameters = {
        "min_offshore_wire_usd": 10000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_usd = float(params["min_offshore_wire_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            offshore_txs = [
                t for t in txs
                if float(t["amount_usd"]) >= min_usd
                and (
                    t["origin_country"] in OFFSHORE_FINANCIAL_CENTERS
                    or t["destination_country"] in OFFSHORE_FINANCIAL_CENTERS
                )
            ]
            if offshore_txs:
                total_usd = round(sum(float(t["amount_usd"]) for t in offshore_txs), 2)
                havens = sorted(
                    ({t["origin_country"] for t in offshore_txs} | {t["destination_country"] for t in offshore_txs})
                    & OFFSHORE_FINANCIAL_CENTERS
                )
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=91.0,
                        customer_id=offshore_txs[0]["customer_id"],
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in offshore_txs],
                        trigger_narrative=(
                            f"Account routed {len(offshore_txs)} high-value transfer(s) totaling ${total_usd:,.2f} "
                            f"through offshore secrecy jurisdiction(s): {', '.join(havens)}."
                        ),
                        evidence_metrics={
                            "offshore_jurisdictions": havens,
                            "tx_count": len(offshore_txs),
                            "total_offshore_usd": total_usd,
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


class ImpossibleTravelVelocityDetector(BaseTypologyDetector):
    rule_id = "AML-GEO-003"
    rule_name = "Impossible Travel Geolocation Velocity Conflict (> 800 km/h)"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "FFIEC Authentication & Access Risk Guidelines"
    default_parameters = {
        "max_plausible_speed_kmh": 800.0,
        "min_distance_km": 500.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        max_speed = float(params["max_plausible_speed_kmh"])
        min_dist = float(params["min_distance_km"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            geo_txs = [
                t for t in txs
                if t.get("geo_lat") is not None and t.get("geo_lon") is not None
            ]
            if len(geo_txs) < 2:
                continue
            for idx in range(1, len(geo_txs)):
                t1, t2 = geo_txs[idx - 1], geo_txs[idx]
                dist_km = haversine_km(
                    float(t1["geo_lat"]), float(t1["geo_lon"]),
                    float(t2["geo_lat"]), float(t2["geo_lon"]),
                )
                if dist_km < min_dist:
                    continue
                hours = max(0.05, (parse_iso_ts(t2["tx_timestamp"]) - parse_iso_ts(t1["tx_timestamp"])).total_seconds() / 3600.0)
                speed_kmh = dist_km / hours
                if speed_kmh > max_speed:
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=92.0,
                            customer_id=t2["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t1["id"], t2["id"]],
                            trigger_narrative=(
                                f"Impossible travel velocity conflict: Consecutive transactions separated by "
                                f"{dist_km:,.0f} km occurred within {hours:.2f} hours (implied velocity: "
                                f"{speed_kmh:,.0f} km/h > {max_speed:,.0f} km/h limit)."
                            ),
                            evidence_metrics={
                                "distance_km": round(dist_km, 1),
                                "elapsed_hours": round(hours, 2),
                                "implied_speed_kmh": round(speed_kmh, 1),
                                "origin_country_1": t1["origin_country"],
                                "origin_country_2": t2["origin_country"],
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class CrossBorderRemittanceBurstDetector(BaseTypologyDetector):
    rule_id = "AML-GEO-004"
    rule_name = "Cross-Border Remittance Burst Exceeding Customer KYC Footprint"
    family = "GEOGRAPHIC"
    default_severity = "MEDIUM"
    regulatory_citation = "FFIEC BSA/AML Manual — Cross-Border Remittances"
    default_parameters = {
        "min_foreign_tx_count": 3,
        "min_foreign_total_usd": 9000.0,
        "window_hours": 168,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_cnt = int(params["min_foreign_tx_count"])
        min_total = float(params["min_foreign_total_usd"])
        win_delta = timedelta(hours=float(params["window_hours"]))

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            home_countries = {
                cust.get("residence_country", "US"),
                cust.get("nationality_or_reg_country", "US"),
            }
            foreign_out = [
                t for t in txs
                if t["direction"] == "OUTBOUND" and t["destination_country"] not in home_countries
            ]
            if len(foreign_out) < min_cnt:
                continue
            for i, start_tx in enumerate(foreign_out):
                t0 = parse_iso_ts(start_tx["tx_timestamp"])
                win = [t for t in foreign_out[i:] if parse_iso_ts(t["tx_timestamp"]) - t0 <= win_delta]
                total_usd = round(sum(float(t["amount_usd"]) for t in win), 2)
                if len(win) >= min_cnt and total_usd >= min_total:
                    dests = sorted({t["destination_country"] for t in win})
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=81.0,
                            customer_id=start_tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[t["id"] for t in win],
                            trigger_narrative=(
                                f"Cross-border remittance burst outside KYC footprint: {len(win)} outbound transfers "
                                f"totaling ${total_usd:,.2f} sent to {', '.join(dests)} within {params['window_hours']}h."
                            ),
                            evidence_metrics={
                                "foreign_tx_count": len(win),
                                "foreign_total_usd": total_usd,
                                "destination_countries": dests,
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class SanctionsAdjacentTransitRoutingDetector(BaseTypologyDetector):
    rule_id = "AML-GEO-005"
    rule_name = "Sanctions-Adjacent Transit Hub Routing"
    family = "GEOGRAPHIC"
    default_severity = "HIGH"
    regulatory_citation = "FinCEN & BIS Joint Alert FIN-2023-Alert004"
    default_parameters = {
        "min_transit_wire_usd": 15000.0,
        "transit_country_codes": ["AE", "TR", "AM", "KZ", "KG", "GE", "HK"],
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_usd = float(params["min_transit_wire_usd"])
        transit_codes = set(params["transit_country_codes"])
        dual_use_keywords = {"SEMICONDUCTOR", "CNC", "AVIONICS", "MICROELECTRONICS", "BALL BEARING", "TURBINE", "OPTICS", "DUAL-USE", "INDUSTRIAL COMPONENT"}

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            matched = []
            for t in txs:
                if float(t["amount_usd"]) < min_usd:
                    continue
                if t["destination_country"] in transit_codes or t["origin_country"] in transit_codes:
                    memo = (t.get("remittance_purpose") or "").upper()
                    if any(k in memo for k in dual_use_keywords) or t["tx_type"] == "WIRE_INTERNATIONAL":
                        matched.append(t)
            if matched:
                total_usd = round(sum(float(t["amount_usd"]) for t in matched), 2)
                corridors = sorted(
                    ({t["origin_country"] for t in matched} | {t["destination_country"] for t in matched})
                    & transit_codes
                )
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=88.0,
                        customer_id=matched[0]["customer_id"],
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in matched],
                        trigger_narrative=(
                            f"Sanctions-adjacent transit routing: {len(matched)} international wire(s) totaling "
                            f"${total_usd:,.2f} routed via transshipment hub(s) {', '.join(corridors)}."
                        ),
                        evidence_metrics={
                            "transit_hubs": corridors,
                            "tx_count": len(matched),
                            "total_transit_usd": total_usd,
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


# ==============================================================================
# FAMILY E — BEHAVIORAL ANOMALIES, ATO & COMMERCIAL FRAUD (FRD-BEH-001 .. 005)
# ==============================================================================

class ExtremeVelocityZScoreDetector(BaseTypologyDetector):
    rule_id = "FRD-BEH-001"
    rule_name = "Extreme Behavioral Velocity & Z-Score Amount Spike (> 3.0 Sigma)"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "HIGH"
    regulatory_citation = "31 CFR 1020.210(b)(5)"
    default_parameters = {
        "min_z_score": 2.8,
        "min_kyc_monthly_multiple": 1.5,
        "min_tx_amount_usd": 10000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_z = float(params["min_z_score"])
        min_mult = float(params["min_kyc_monthly_multiple"])
        min_amt = float(params["min_tx_amount_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if len(txs) < 4:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            expected_mo = max(1000.0, float(cust.get("expected_monthly_volume_usd", 5000.0)))
            for idx, tx in enumerate(txs):
                amt = float(tx["amount_usd"])
                if amt < min_amt:
                    continue
                peer_amounts = [float(t["amount_usd"]) for j, t in enumerate(txs) if j != idx]
                mean_amt = sum(peer_amounts) / len(peer_amounts)
                variance = sum((x - mean_amt) ** 2 for x in peer_amounts) / max(1, len(peer_amounts) - 1)
                std_dev = max(100.0, math.sqrt(variance))
                z_score = (amt - mean_amt) / std_dev
                kyc_mult = amt / expected_mo
                if z_score >= min_z and kyc_mult >= min_mult:
                    results.append(
                        RuleTriggerResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            family=self.family,
                            severity=self.default_severity,
                            confidence_score=min(96.0, 75.0 + 4.0 * z_score),
                            customer_id=tx["customer_id"],
                            account_id=acct_id,
                            triggered_transaction_ids=[tx["id"]],
                            trigger_narrative=(
                                f"Extreme behavioral amount anomaly: Transaction of ${amt:,.2f} is {z_score:.2f} "
                                f"standard deviations above account mean (${mean_amt:,.2f}) and {kyc_mult:.1f}x "
                                f"the customer's stated monthly KYC expectation (${expected_mo:,.2f})."
                            ),
                            evidence_metrics={
                                "tx_amount_usd": amt,
                                "account_mean_usd": round(mean_amt, 2),
                                "account_std_usd": round(std_dev, 2),
                                "z_score": round(z_score, 2),
                                "kyc_monthly_multiple": round(kyc_mult, 2),
                            },
                            regulatory_citation=self.regulatory_citation,
                        )
                    )
                    break
        return results


class AccountTakeoverRapidDrainDetector(BaseTypologyDetector):
    rule_id = "FRD-BEH-002"
    rule_name = "Account Takeover (ATO): New Device + Rapid Balance Drain (> 75%)"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory FIN-2016-A005"
    default_parameters = {
        "min_drain_ratio": 0.75,
        "min_drain_amount_usd": 5000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_ratio = float(params["min_drain_ratio"])
        min_amt = float(params["min_drain_amount_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            known_devices: Set[str] = set()
            for idx, tx in enumerate(txs):
                dev = tx.get("device_fingerprint")
                if idx == 0 and dev:
                    known_devices.add(dev)
                    continue
                if tx["direction"] == "OUTBOUND" and float(tx["amount_usd"]) >= min_amt:
                    amt = float(tx["amount_usd"])
                    bal_after = max(0.0, float(tx.get("balance_after_usd", 0.0)))
                    prior_balance = amt + bal_after
                    drain_ratio = amt / prior_balance if prior_balance > 0 else 0.0
                    is_new_device = bool(dev and known_devices and dev not in known_devices)
                    if is_new_device and drain_ratio >= min_ratio:
                        results.append(
                            RuleTriggerResult(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                family=self.family,
                                severity=self.default_severity,
                                confidence_score=96.0,
                                customer_id=tx["customer_id"],
                                account_id=acct_id,
                                triggered_transaction_ids=[tx["id"]],
                                trigger_narrative=(
                                    f"Account Takeover (ATO) signature: Unrecognized device '{dev}' initiated "
                                    f"an outbound {tx['tx_type']} of ${amt:,.2f}, draining {drain_ratio * 100:.1f}% "
                                    f"of prior account balance (${prior_balance:,.2f})."
                                ),
                                evidence_metrics={
                                    "new_device_fingerprint": dev,
                                    "prior_known_devices": sorted(known_devices),
                                    "drain_amount_usd": amt,
                                    "prior_balance_usd": round(prior_balance, 2),
                                    "drain_ratio": round(drain_ratio, 4),
                                },
                                regulatory_citation=self.regulatory_citation,
                            )
                        )
                        break
                if dev:
                    known_devices.add(dev)
        return results


class ElderFinancialExploitationDetector(BaseTypologyDetector):
    rule_id = "FRD-BEH-003"
    rule_name = "Elder / Senior Customer Sudden High-Value Outflow Spike"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "CRITICAL"
    regulatory_citation = "FinCEN Advisory FIN-2022-A002 (Elder Financial Exploitation)"
    default_parameters = {
        "min_senior_age_years": 65,
        "min_outflow_usd": 8000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        min_age = int(params["min_senior_age_years"])
        min_outflow = float(params["min_outflow_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            if cust.get("customer_type") != "INDIVIDUAL":
                continue
            dob_str = cust.get("date_of_birth_or_inc", "1980-01-01")
            try:
                birth_year = int(dob_str[:4])
            except ValueError:
                continue
            age = 2026 - birth_year
            if age < min_age:
                continue

            large_outflows = [
                t for t in txs
                if t["direction"] == "OUTBOUND"
                and t["tx_type"] in ("WIRE_INTERNATIONAL", "WIRE_DOMESTIC", "CASH_WITHDRAWAL", "CRYPTO_EXCHANGE")
                and float(t["amount_usd"]) >= min_outflow
            ]
            if large_outflows:
                total_usd = round(sum(float(t["amount_usd"]) for t in large_outflows), 2)
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=91.0,
                        customer_id=cust["id"],
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in large_outflows],
                        trigger_narrative=(
                            f"Potential Elder Financial Exploitation: Senior customer (age {age}) executed "
                            f"{len(large_outflows)} high-risk outbound transfer(s) totaling ${total_usd:,.2f}."
                        ),
                        evidence_metrics={
                            "customer_age_years": age,
                            "outflow_count": len(large_outflows),
                            "total_outflow_usd": total_usd,
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


class CommercialKybMccMismatchDetector(BaseTypologyDetector):
    rule_id = "FRD-BEH-004"
    rule_name = "Commercial KYB Profile & High-Risk MCC Spend Mismatch"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "MEDIUM"
    regulatory_citation = "FFIEC BSA/AML — Business Account Activity Inconsistent with Stated Industry"
    default_parameters = {
        "high_risk_mccs": ["7995", "5944", "5933", "6051", "4829"],
        "min_mismatch_spend_usd": 4000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        risky_mccs = set(params["high_risk_mccs"])
        min_spend = float(params["min_mismatch_spend_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            if not txs:
                continue
            cust = context.customers_by_id.get(txs[0]["customer_id"], {})
            if cust.get("customer_type") != "BUSINESS":
                continue

            mismatch_txs = [
                t for t in txs
                if t.get("mcc_code") in risky_mccs
            ]
            total_spend = round(sum(float(t["amount_usd"]) for t in mismatch_txs), 2)
            if mismatch_txs and total_spend >= min_spend:
                mccs_hit = sorted({t["mcc_code"] for t in mismatch_txs if t.get("mcc_code")})
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=83.0,
                        customer_id=cust["id"],
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in mismatch_txs],
                        trigger_narrative=(
                            f"Commercial KYB profile mismatch: Business entity '{cust.get('legal_name')}' "
                            f"({cust.get('occupation_or_industry')}) spent ${total_spend:,.2f} across high-risk "
                            f"MCC codes ({', '.join(mccs_hit)}: gaming/jewelry/quasi-cash)."
                        ),
                        evidence_metrics={
                            "stated_industry": cust.get("occupation_or_industry"),
                            "mismatched_mccs": mccs_hit,
                            "total_mismatch_spend_usd": total_spend,
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results


class OffHoursAutomatedBurstDetector(BaseTypologyDetector):
    rule_id = "FRD-BEH-005"
    rule_name = "Off-Hours Midnight Automated Scripting Burst (01:00–04:59 UTC)"
    family = "BEHAVIORAL_FRAUD"
    default_severity = "MEDIUM"
    regulatory_citation = "FFIEC Cybersecurity & Automated Bot Fraud Detection Indicators"
    default_parameters = {
        "start_hour_utc": 1,
        "end_hour_utc": 4,
        "min_burst_count": 4,
        "min_burst_total_usd": 4000.0,
    }

    def evaluate(
        self, context: TypologyEvaluationContext, override_params: Optional[Dict[str, Any]] = None
    ) -> List[RuleTriggerResult]:
        params = self.get_effective_params(override_params)
        start_hr = int(params["start_hour_utc"])
        end_hr = int(params["end_hour_utc"])
        min_cnt = int(params["min_burst_count"])
        min_usd = float(params["min_burst_total_usd"])

        results: List[RuleTriggerResult] = []
        for acct_id, txs in context.tx_by_account.items():
            night_txs = [
                t for t in txs
                if t["direction"] == "OUTBOUND"
                and start_hr <= parse_iso_ts(t["tx_timestamp"]).hour <= end_hr
            ]
            total_night = round(sum(float(t["amount_usd"]) for t in night_txs), 2)
            if len(night_txs) >= min_cnt and total_night >= min_usd:
                results.append(
                    RuleTriggerResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        family=self.family,
                        severity=self.default_severity,
                        confidence_score=80.0,
                        customer_id=night_txs[0]["customer_id"],
                        account_id=acct_id,
                        triggered_transaction_ids=[t["id"] for t in night_txs],
                        trigger_narrative=(
                            f"Off-hours automated velocity burst: {len(night_txs)} outbound transfers "
                            f"totaling ${total_night:,.2f} executed between {start_hr:02d}:00 and {end_hr:02d}:59 UTC."
                        ),
                        evidence_metrics={
                            "off_hours_tx_count": len(night_txs),
                            "off_hours_total_usd": total_night,
                            "window_utc": f"{start_hr:02d}:00-{end_hr:02d}:59",
                        },
                        regulatory_citation=self.regulatory_citation,
                    )
                )
        return results
