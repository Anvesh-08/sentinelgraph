"""
Base abstractions and evaluation context for the 25-Rule AML & Fraud Typology Engine.
Provides helper utilities for parsing ISO-8601 timestamps, computing rolling time windows,
calculating Haversine geolocation distance, and formatting explainable trigger narratives.
"""
import math
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.domain import RuleTriggerResult


def parse_iso_ts(ts_str: str) -> datetime:
    cleaned = ts_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Computes great-circle distance in kilometers between two WGS84 coordinates."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    return 2.0 * r * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


class TypologyEvaluationContext:
    """
    Pre-indexed ledger snapshot passed to typology evaluators so rules can inspect
    account history, customer KYC profiles, counterparty mappings, and shared attributes
    in O(1) lookup time.
    """

    def __init__(
        self,
        customers_by_id: Dict[str, Dict[str, Any]],
        accounts_by_id: Dict[str, Dict[str, Any]],
        transactions: List[Dict[str, Any]],
        flagged_account_ids: Optional[set] = None,
    ) -> None:
        self.customers_by_id = customers_by_id
        self.accounts_by_id = accounts_by_id
        self.all_transactions = sorted(transactions, key=lambda t: t["tx_timestamp"])
        self.flagged_account_ids = flagged_account_ids or set()

        self.tx_by_account: Dict[str, List[Dict[str, Any]]] = {}
        self.tx_by_customer: Dict[str, List[Dict[str, Any]]] = {}
        self.inbound_by_target_account: Dict[str, List[Dict[str, Any]]] = {}
        self.accounts_by_device: Dict[str, set] = {}
        self.accounts_by_ip: Dict[str, set] = {}

        for tx in self.all_transactions:
            acct_id = tx["account_id"]
            cust_id = tx["customer_id"]
            self.tx_by_account.setdefault(acct_id, []).append(tx)
            self.tx_by_customer.setdefault(cust_id, []).append(tx)

            if tx["direction"] == "INBOUND":
                self.inbound_by_target_account.setdefault(acct_id, []).append(tx)
            elif tx["direction"] == "OUTBOUND" and tx.get("counterparty_account_id"):
                self.inbound_by_target_account.setdefault(tx["counterparty_account_id"], []).append(tx)

            dev = tx.get("device_fingerprint")
            if dev:
                self.accounts_by_device.setdefault(dev, set()).add(acct_id)

            ip = tx.get("ip_address")
            if ip:
                self.accounts_by_ip.setdefault(ip, set()).add(acct_id)


class BaseTypologyDetector(ABC):
    """Abstract base class for all 25 AML & Fraud typology detectors."""

    rule_id: str = ""
    rule_name: str = ""
    family: str = ""
    default_severity: str = "HIGH"
    regulatory_citation: str = ""
    description: str = ""
    default_parameters: Dict[str, Any] = {}

    def get_effective_params(self, override_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged = dict(self.default_parameters)
        if override_params:
            merged.update(override_params)
        return merged

    @abstractmethod
    def evaluate(
        self,
        context: TypologyEvaluationContext,
        override_params: Optional[Dict[str, Any]] = None,
    ) -> List[RuleTriggerResult]:
        """Evaluates the ledger context and returns a list of RuleTriggerResult objects."""
        raise NotImplementedError
