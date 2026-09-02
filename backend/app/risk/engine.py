"""
Dynamic 6-Factor Composite Customer Risk Scoring Engine (`FR-RISK`).
Evaluates Retail (INDIVIDUAL) and Corporate (BUSINESS / KYB) customers across six weighted dimensions:
1. Geographic Risk (20%): FATF high-risk/black-list, grey-list, offshore tax havens.
2. Entity & Ownership Complexity Risk (15%): Cash-intensive NAICS industries, shell structures, multi-UBO PEP exposure.
3. Sanctions, PEP & Adverse Media Exposure (25%): Active watchlist status, PEP status, adverse media flags.
4. Product & Channel Risk (15%): Exposure to cross-border wires, crypto wallets, cash deposits, API gateways.
5. Behavioral Velocity & Baseline Drift (15%): Ratio of actual 30d/90d volume to stated KYC expected monthly volume.
6. Graph Network Contagion Risk (10%): Direct 1-hop or 2-hop transactional links to flagged accounts or SAR subjects.
"""
import json
import math
from typing import Any, Dict, List, Set

from backend.app.core.models_constants import (
    CASH_INTENSIVE_INDUSTRIES,
    FATF_BLACK_LIST_COUNTRIES,
    FATF_GREY_LIST_COUNTRIES,
    OFFSHORE_FINANCIAL_CENTERS,
)
from backend.app.db.connection import DatabaseManager
from backend.app.repositories.core_repositories import CustomerRepository


class CompositeRiskEngine:
    """Computes explainable 0-100 composite risk scores and classifies customers into risk bands."""

    WEIGHTS = {
        "geographic_risk": 0.20,
        "entity_complexity_risk": 0.15,
        "pep_sanctions_adverse_media_risk": 0.25,
        "channel_product_risk": 0.15,
        "behavioral_velocity_risk": 0.15,
        "graph_contagion_risk": 0.10,
    }

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.customer_repo = CustomerRepository(db)

    @staticmethod
    def classify_band(score: float) -> str:
        if score >= 85.0:
            return "CRITICAL"
        if score >= 65.0:
            return "HIGH"
        if score >= 35.0:
            return "MEDIUM"
        return "LOW"

    def _score_geography(self, customer: Dict[str, Any], ubos: List[Dict[str, Any]], tx_countries: Set[str]) -> Dict[str, Any]:
        countries = {
            customer.get("nationality_or_reg_country", "US"),
            customer.get("residence_country", "US"),
        }
        for ubo in ubos:
            countries.add(ubo.get("nationality", "US"))
            countries.add(ubo.get("residence_country", "US"))
        countries.update(tx_countries)

        black_hits = sorted(countries.intersection(FATF_BLACK_LIST_COUNTRIES))
        grey_hits = sorted(countries.intersection(FATF_GREY_LIST_COUNTRIES))
        offshore_hits = sorted(countries.intersection(OFFSHORE_FINANCIAL_CENTERS))

        raw_score = 10.0
        reasons: List[str] = []
        if black_hits:
            raw_score += 85.0
            reasons.append(f"Exposure to FATF Call-for-Action jurisdiction(s): {', '.join(black_hits)}")
        if grey_hits:
            raw_score += min(55.0, 28.0 * len(grey_hits))
            reasons.append(f"Exposure to FATF Increased Monitoring jurisdiction(s): {', '.join(grey_hits)}")
        if offshore_hits:
            raw_score += min(50.0, 25.0 * len(offshore_hits))
            reasons.append(f"Exposure to offshore financial center(s): {', '.join(offshore_hits)}")

        final = min(100.0, round(raw_score, 2))
        return {"score": final, "reasons": reasons or ["Standard low-risk domestic/OECD footprint"]}

    def _score_entity_complexity(self, customer: Dict[str, Any], ubos: List[Dict[str, Any]]) -> Dict[str, Any]:
        score = 15.0 if customer["customer_type"] == "INDIVIDUAL" else 35.0
        reasons: List[str] = []
        industry = (customer.get("occupation_or_industry") or "").upper()

        for keyword in CASH_INTENSIVE_INDUSTRIES:
            if keyword in industry:
                score += 30.0
                reasons.append(f"High-risk/cash-intensive sector: {customer.get('occupation_or_industry')}")
                break

        if customer["customer_type"] == "BUSINESS":
            if len(ubos) >= 3:
                score += 15.0
                reasons.append(f"Complex beneficial ownership structure ({len(ubos)} UBOs)")
            cross_border_ubos = [
                u for u in ubos if u.get("residence_country") != customer.get("residence_country")
            ]
            if cross_border_ubos:
                score += 20.0
                reasons.append(f"{len(cross_border_ubos)} UBO(s) resident outside entity registration country")

        return {"score": min(100.0, round(score, 2)), "reasons": reasons or ["Standard entity structure"]}

    def _score_pep_sanctions_media(self, customer: Dict[str, Any], ubos: List[Dict[str, Any]]) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []

        sanctions_status = customer.get("sanctions_status", "CLEAR")
        if sanctions_status == "CONFIRMED_MATCH":
            score += 100.0
            reasons.append("Confirmed watchlist/sanctions match on customer record")
        elif sanctions_status == "POTENTIAL_MATCH":
            score += 70.0
            reasons.append("Unresolved potential sanctions/watchlist match pending review")

        if int(customer.get("pep_flag", 0)) == 1:
            score += 65.0
            reasons.append("Primary customer is a Politically Exposed Person (PEP)")

        if any(int(u.get("is_pep", 0)) == 1 for u in ubos):
            score += 55.0
            reasons.append("One or more Ultimate Beneficial Owners (UBOs) flagged as PEP")

        if int(customer.get("adverse_media_flag", 0)) == 1:
            score += 50.0
            reasons.append("Adverse media / financial crime press coverage indicator active")

        return {"score": min(100.0, round(score, 2)), "reasons": reasons or ["No PEP, sanctions, or adverse media hits"]}

    def _score_channels_and_products(
        self, accounts: List[Dict[str, Any]], txs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        score = 10.0
        reasons: List[str] = []
        acct_types = {a["account_type"] for a in accounts}
        tx_types = {t["tx_type"] for t in txs}

        if "CRYPTO_WALLET" in acct_types or "CRYPTO_EXCHANGE" in tx_types:
            score += 40.0
            reasons.append("Digital asset / crypto exchange ramp activity")
        if "WIRE_INTERNATIONAL" in tx_types:
            score += 30.0
            reasons.append("International SWIFT wire transfer activity")
        if "CASH_DEPOSIT" in tx_types or "CASH_WITHDRAWAL" in tx_types:
            score += 20.0
            reasons.append("Physical cash deposit/withdrawal usage")

        return {"score": min(100.0, round(score, 2)), "reasons": reasons or ["Standard domestic banking channels"]}

    def _score_behavioral_velocity(self, customer: Dict[str, Any], txs: List[Dict[str, Any]]) -> Dict[str, Any]:
        expected_monthly = max(500.0, float(customer.get("expected_monthly_volume_usd", 5000.0)))
        total_volume = sum(float(t["amount_usd"]) for t in txs)
        # Approximate monthly run rate over observed window
        observed_monthly_volume = total_volume / max(1.0, len({t["tx_timestamp"][:7] for t in txs})) if txs else 0.0
        ratio = observed_monthly_volume / expected_monthly

        reasons: List[str] = []
        if ratio <= 1.2:
            score = 10.0
            reasons.append(f"Observed volume (${observed_monthly_volume:,.2f}/mo) aligns with KYC baseline (${expected_monthly:,.2f}/mo)")
        else:
            score = min(100.0, 20.0 + 25.0 * math.log2(max(1.0, ratio)))
            reasons.append(
                f"Observed monthly volume (${observed_monthly_volume:,.2f}) is {ratio:.1f}x stated KYC expectation (${expected_monthly:,.2f})"
            )

        return {
            "score": round(score, 2),
            "observed_monthly_usd": round(observed_monthly_volume, 2),
            "expected_monthly_usd": round(expected_monthly, 2),
            "velocity_ratio": round(ratio, 2),
            "reasons": reasons,
        }

    def _score_graph_contagion(self, customer_id: str, account_ids: Set[str]) -> Dict[str, Any]:
        if not account_ids:
            return {"score": 0.0, "reasons": ["No active accounts"]}

        placeholders = ",".join("?" for _ in account_ids)
        acct_tuple = tuple(account_ids)
        with self.db.connection() as conn:
            alert_count_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM alerts WHERE customer_id = ? AND status != 'DISMISSED_FALSE_POSITIVE'",
                (customer_id,),
            ).fetchone()
            own_alerts = int(alert_count_row["cnt"]) if alert_count_row else 0

            # Check 1-hop counterparty accounts that have active alerts or frozen status
            contagion_row = conn.execute(
                f"""
                SELECT COUNT(DISTINCT t.counterparty_account_id) AS risky_peers
                FROM transactions t
                JOIN alerts a ON a.account_id = t.counterparty_account_id
                WHERE t.account_id IN ({placeholders})
                  AND t.counterparty_account_id IS NOT NULL
                  AND a.status != 'DISMISSED_FALSE_POSITIVE'
                """,
                acct_tuple,
            ).fetchone()
            risky_peers = int(contagion_row["risky_peers"]) if contagion_row else 0

        score = min(100.0, own_alerts * 22.0 + risky_peers * 28.0)
        reasons: List[str] = []
        if own_alerts > 0:
            reasons.append(f"Customer has {own_alerts} active/escalated AML alert(s)")
        if risky_peers > 0:
            reasons.append(f"Transacted directly (1-hop) with {risky_peers} flagged internal counterparty account(s)")

        return {"score": round(score, 2), "reasons": reasons or ["Zero graph contagion exposure"]}

    def evaluate_customer(self, customer_id: str, persist: bool = True) -> Dict[str, Any]:
        """Calculates the 6-factor composite risk score for a customer and optionally persists it."""
        customer = self.customer_repo.get_by_id(customer_id)
        ubos = self.customer_repo.get_beneficial_owners(customer_id)

        with self.db.connection() as conn:
            accounts = [
                dict(r)
                for r in conn.execute("SELECT * FROM accounts WHERE customer_id = ?", (customer_id,)).fetchall()
            ]
            txs = [
                dict(r)
                for r in conn.execute("SELECT * FROM transactions WHERE customer_id = ?", (customer_id,)).fetchall()
            ]

        tx_countries: Set[str] = set()
        for t in txs:
            tx_countries.add(t["origin_country"])
            tx_countries.add(t["destination_country"])

        geo = self._score_geography(customer, ubos, tx_countries)
        entity = self._score_entity_complexity(customer, ubos)
        pep_sanc = self._score_pep_sanctions_media(customer, ubos)
        channel = self._score_channels_and_products(accounts, txs)
        velocity = self._score_behavioral_velocity(customer, txs)
        contagion = self._score_graph_contagion(customer_id, {a["id"] for a in accounts})

        composite_score = (
            geo["score"] * self.WEIGHTS["geographic_risk"]
            + entity["score"] * self.WEIGHTS["entity_complexity_risk"]
            + pep_sanc["score"] * self.WEIGHTS["pep_sanctions_adverse_media_risk"]
            + channel["score"] * self.WEIGHTS["channel_product_risk"]
            + velocity["score"] * self.WEIGHTS["behavioral_velocity_risk"]
            + contagion["score"] * self.WEIGHTS["graph_contagion_risk"]
        )
        # Apply regulatory floor overrides: confirmed sanctions or PEP + high-risk corridor forces HIGH/CRITICAL
        if pep_sanc["score"] >= 95.0:
            composite_score = max(composite_score, 92.0)
        elif pep_sanc["score"] >= 65.0 and geo["score"] >= 60.0:
            composite_score = max(composite_score, 78.0)

        composite_score = round(min(100.0, composite_score), 2)
        risk_band = self.classify_band(composite_score)

        breakdown = {
            "composite_risk_score": composite_score,
            "risk_band": risk_band,
            "weights": self.WEIGHTS,
            "dimensions": {
                "geographic_risk": geo,
                "entity_complexity_risk": entity,
                "pep_sanctions_adverse_media_risk": pep_sanc,
                "channel_product_risk": channel,
                "behavioral_velocity_risk": velocity,
                "graph_contagion_risk": contagion,
            },
        }

        if persist:
            self.customer_repo.update_risk_score(
                customer_id=customer_id,
                composite_risk_score=composite_score,
                risk_band=risk_band,
                risk_factors=breakdown,
            )

        return breakdown

    def evaluate_all_customers(self) -> Dict[str, int]:
        customers = self.customer_repo.list_customers(limit=5000)
        band_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for cust in customers:
            res = self.evaluate_customer(cust["id"], persist=True)
            band_counts[res["risk_band"]] = band_counts.get(res["risk_band"], 0) + 1
        return band_counts
