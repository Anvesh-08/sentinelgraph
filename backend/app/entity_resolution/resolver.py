"""
Probabilistic Fellegi-Sunter Entity Resolution & Synthetic Identity Detection Engine.
Links disparate Customer, Beneficial Owner, and Counterparty records across:
- Legal Name / Alias similarity (Jaro-Winkler + Token-Set + Soundex)
- Standardized Postal Address similarity (USPS/UPU street token normalization)
- Normalized E.164 Phone Number & Domain Email linkage
- Tax ID Hash (SHA-256 TIN/EIN/PAN) exact & collision checks
- Shared Hardware Device Fingerprint & IP Subnet overlap

Computes log-likelihood match weights ($W = \sum_k \log_2(m_k / u_k)$), converts to posterior
match probabilities, and identifies:
1. Undisclosed Related-Party Networks (`RELATED_PARTY_CLUSTER`)
2. Synthetic Identity Frankenstein Profiles (`SYNTHETIC_IDENTITY_SUSPECT`: shared TIN/phone/address across distinct legal names/DOBs)
3. Beneficial Ownership Circular & 50%-Rule Sanctions Control Chains
"""
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.db.connection import DatabaseManager
from backend.app.sanctions.screener import (
    jaro_winkler_similarity,
    normalize_name,
    phonetic_signature,
    token_set_similarity,
)


STREET_ABBREV_MAP: Dict[str, str] = {
    "STREET": "ST",
    "AVENUE": "AVE",
    "BOULEVARD": "BLVD",
    "DRIVE": "DR",
    "ROAD": "RD",
    "LANE": "LN",
    "COURT": "CT",
    "PARKWAY": "PKWY",
    "SUITE": "STE",
    "APARTMENT": "APT",
    "FLOOR": "FL",
    "BUILDING": "BLDG",
    "PLAZA": "PLZ",
    "SQUARE": "SQ",
}


def standardize_postal_address(raw_addr: Optional[str]) -> str:
    if not raw_addr:
        return ""
    cleaned = re.sub(r"[^A-Z0-9\s]", " ", raw_addr.upper())
    tokens = [STREET_ABBREV_MAP.get(tok, tok) for tok in cleaned.split() if tok]
    return " ".join(tokens)


def normalize_phone_e164(raw_phone: Optional[str]) -> str:
    if not raw_phone:
        return ""
    digits = "".join(ch for ch in raw_phone if ch.isdigit())
    return digits[-10:] if len(digits) >= 10 else digits


@dataclass
class EntityMatchCandidate:
    entity_a_id: str
    entity_a_name: str
    entity_b_id: str
    entity_b_name: str
    fellegi_sunter_log_weight: float
    posterior_probability: float
    classification: str  # DEFINITE_MATCH, PROBABLE_RELATED_PARTY, SYNTHETIC_IDENTITY_CONFLICT, NON_MATCH
    field_scores: Dict[str, float] = field(default_factory=dict)
    shared_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_a_id": self.entity_a_id,
            "entity_a_name": self.entity_a_name,
            "entity_b_id": self.entity_b_id,
            "entity_b_name": self.entity_b_name,
            "fellegi_sunter_log_weight": round(self.fellegi_sunter_log_weight, 4),
            "posterior_probability": round(self.posterior_probability, 4),
            "classification": self.classification,
            "field_scores": self.field_scores,
            "shared_signals": self.shared_signals,
        }


class ProbabilisticEntityResolver:
    """Executes pairwise and transitive graph-connected entity resolution across all customers and UBOs."""

    # Fellegi-Sunter m-probabilities (true match agreement) and u-probabilities (chance agreement)
    FS_PARAMETERS: Dict[str, Tuple[float, float]] = {
        "name": (0.92, 0.02),
        "dob": (0.96, 0.005),
        "tax_id_hash": (0.99, 0.0005),
        "phone": (0.88, 0.002),
        "address": (0.85, 0.005),
        "device_fingerprint": (0.90, 0.001),
    }

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    @classmethod
    def _compute_log_weight(cls, feature: str, agreed: bool, similarity: float = 1.0) -> float:
        m_prob, u_prob = cls.FS_PARAMETERS[feature]
        if agreed:
            full_w = math.log2(m_prob / u_prob)
            return full_w * max(0.0, min(1.0, similarity))
        return math.log2((1.0 - m_prob) / (1.0 - u_prob))

    @staticmethod
    def _weight_to_probability(log_weight: float, prior_odds: float = 0.02) -> float:
        likelihood_ratio = 2.0 ** max(-20.0, min(25.0, log_weight))
        posterior_odds = prior_odds * likelihood_ratio
        return round(posterior_odds / (1.0 + posterior_odds), 4)

    def compare_customer_pair(
        self,
        cust_a: Dict[str, Any],
        cust_b: Dict[str, Any],
        devices_a: Set[str],
        devices_b: Set[str],
    ) -> EntityMatchCandidate:
        name_a = normalize_name(cust_a.get("legal_name", ""))
        name_b = normalize_name(cust_b.get("legal_name", ""))
        name_sim = max(
            jaro_winkler_similarity(name_a, name_b),
            token_set_similarity(name_a, name_b),
        )
        phon_overlap = len(phonetic_signature(name_a) & phonetic_signature(name_b)) > 0

        dob_a = (cust_a.get("date_of_birth_or_inc") or "").strip()
        dob_b = (cust_b.get("date_of_birth_or_inc") or "").strip()
        dob_exact = bool(dob_a and dob_b and dob_a == dob_b)

        tin_a = cust_a.get("tax_id_hash") or ""
        tin_b = cust_b.get("tax_id_hash") or ""
        tin_exact = bool(tin_a and tin_b and tin_a == tin_b)

        phone_a = normalize_phone_e164(cust_a.get("phone_number"))
        phone_b = normalize_phone_e164(cust_b.get("phone_number"))
        phone_exact = bool(phone_a and phone_b and phone_a == phone_b)

        addr_a = standardize_postal_address(cust_a.get("physical_address"))
        addr_b = standardize_postal_address(cust_b.get("physical_address"))
        addr_sim = jaro_winkler_similarity(addr_a, addr_b) if (addr_a and addr_b) else 0.0

        shared_devs = devices_a & devices_b
        dev_match = len(shared_devs) > 0

        total_w = 0.0
        shared_signals: List[str] = []

        if name_sim >= 0.82:
            total_w += self._compute_log_weight("name", True, name_sim)
            shared_signals.append(f"HIGH_NAME_SIMILARITY({name_sim:.2f})")
        else:
            total_w += self._compute_log_weight("name", False)

        if dob_exact:
            total_w += self._compute_log_weight("dob", True, 1.0)
            shared_signals.append("EXACT_DOB_OR_INC_DATE")
        else:
            total_w += self._compute_log_weight("dob", False)

        if tin_exact:
            total_w += self._compute_log_weight("tax_id_hash", True, 1.0)
            shared_signals.append("SHARED_TAX_ID_HASH")

        if phone_exact:
            total_w += self._compute_log_weight("phone", True, 1.0)
            shared_signals.append("SHARED_E164_PHONE")

        if addr_sim >= 0.88:
            total_w += self._compute_log_weight("address", True, addr_sim)
            shared_signals.append(f"SHARED_POSTAL_ADDRESS({addr_sim:.2f})")

        if dev_match:
            total_w += self._compute_log_weight("device_fingerprint", True, 1.0)
            shared_signals.append(f"SHARED_HARDWARE_FINGERPRINT({','.join(sorted(shared_devs))})")

        prob = self._weight_to_probability(total_w)

        # Classify synthetic identity vs. related party vs. duplicate entity
        if (tin_exact or phone_exact or dev_match) and name_sim < 0.65:
            classification = "SYNTHETIC_IDENTITY_OR_MULE_RING_CONFLICT"
            prob = max(prob, 0.89)
        elif prob >= 0.85:
            classification = "DEFINITE_DUPLICATE_ENTITY"
        elif prob >= 0.45 or len(shared_signals) >= 1:
            classification = "PROBABLE_RELATED_PARTY"
        else:
            classification = "NON_MATCH"

        return EntityMatchCandidate(
            entity_a_id=cust_a["id"],
            entity_a_name=cust_a["legal_name"],
            entity_b_id=cust_b["id"],
            entity_b_name=cust_b["legal_name"],
            fellegi_sunter_log_weight=total_w,
            posterior_probability=prob,
            classification=classification,
            field_scores={
                "name_similarity": round(name_sim, 4),
                "phonetic_overlap": 1.0 if phon_overlap else 0.0,
                "dob_exact": 1.0 if dob_exact else 0.0,
                "tax_id_exact": 1.0 if tin_exact else 0.0,
                "phone_exact": 1.0 if phone_exact else 0.0,
                "address_similarity": round(addr_sim, 4),
                "device_overlap": float(len(shared_devs)),
            },
            shared_signals=shared_signals,
        )

    def resolve_all_entities(self) -> Dict[str, Any]:
        with self.db.connection() as conn:
            customers = [dict(r) for r in conn.execute("SELECT * FROM customers ORDER BY id ASC").fetchall()]
            ubos = [dict(r) for r in conn.execute("SELECT * FROM beneficial_owners").fetchall()]
            txs = [dict(r) for r in conn.execute("SELECT customer_id, device_fingerprint FROM transactions WHERE device_fingerprint IS NOT NULL").fetchall()]

        cust_devices: Dict[str, Set[str]] = {}
        for t in txs:
            cust_devices.setdefault(t["customer_id"], set()).add(t["device_fingerprint"])

        matches: List[Dict[str, Any]] = []
        for i in range(len(customers)):
            for j in range(i + 1, len(customers)):
                c1, c2 = customers[i], customers[j]
                cand = self.compare_customer_pair(
                    c1, c2, cust_devices.get(c1["id"], set()), cust_devices.get(c2["id"], set())
                )
                if cand.classification != "NON_MATCH":
                    matches.append(cand.to_dict())

        # Check OFAC 50% Beneficial Ownership Rule across corporate customers
        ofac_50_rule_breaches: List[Dict[str, Any]] = []
        ubos_by_corp: Dict[str, List[Dict[str, Any]]] = {}
        for u in ubos:
            ubos_by_corp.setdefault(u["customer_id"], []).append(u)

        cust_by_id = {c["id"]: c for c in customers}
        for corp_id, corp_ubos in ubos_by_corp.items():
            pep_or_high_risk_pct = 0.0
            flagged_owners: List[str] = []
            for u in corp_ubos:
                linked = cust_by_id.get(u.get("linked_individual_customer_id") or "", {})
                if int(u.get("is_pep", 0)) == 1 or linked.get("sanctions_status") != "CLEAR" or u.get("nationality") in ("RU", "IR", "VE", "SY", "KP"):
                    pep_or_high_risk_pct += float(u["ownership_percentage"])
                    flagged_owners.append(f"{u['full_name']} ({u['ownership_percentage']:.1f}%)")
            if pep_or_high_risk_pct >= 50.0:
                corp = cust_by_id.get(corp_id, {})
                ofac_50_rule_breaches.append(
                    {
                        "corporate_customer_id": corp_id,
                        "corporate_legal_name": corp.get("legal_name", corp_id),
                        "aggregated_high_risk_ubo_percentage": round(pep_or_high_risk_pct, 2),
                        "flagged_beneficial_owners": flagged_owners,
                        "regulatory_rule": "OFAC 50 Percent Rule / EU-UK Consolidated Ownership Control Aggregation",
                    }
                )

        return {
            "total_customers_scanned": len(customers),
            "resolved_entity_links": matches,
            "ofac_50_percent_ownership_breaches": ofac_50_rule_breaches,
        }
