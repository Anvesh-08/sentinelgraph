"""
Data access repositories using 100% parameterized SQL queries.
Provides clean CRUD and domain query methods for Users, Customers, Accounts,
Transactions, Alerts, Cases, SARs, Rules, Simulations, and Watchlists.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.core.exceptions import ResourceNotFoundError
from backend.app.db.connection import DatabaseManager


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def get_by_id(self, user_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ResourceNotFoundError("User", user_id)
        return dict(row)

    def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT id, username, email, full_name, role, is_active, last_login_at, created_at FROM users ORDER BY username ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def update_last_login(self, user_id: str) -> None:
        with self.db.connection() as conn:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (_now_iso(), user_id))


class CustomerRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def get_by_id(self, customer_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not row:
            raise ResourceNotFoundError("Customer", customer_id)
        data = dict(row)
        data["risk_factors"] = json.loads(data.pop("risk_factors_json") or "{}")
        return data

    def list_customers(
        self,
        risk_band: Optional[str] = None,
        customer_type: Optional[str] = None,
        pep_flag: Optional[int] = None,
        search: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM customers WHERE 1=1"
        params: List[Any] = []
        if risk_band:
            query += " AND risk_band = ?"
            params.append(risk_band)
        if customer_type:
            query += " AND customer_type = ?"
            params.append(customer_type)
        if pep_flag is not None:
            query += " AND pep_flag = ?"
            params.append(int(pep_flag))
        if search:
            query += " AND (legal_name LIKE ? OR external_ref LIKE ? OR occupation_or_industry LIKE ?)"
            wildcard = f"%{search}%"
            params.extend([wildcard, wildcard, wildcard])
        query += " ORDER BY composite_risk_score DESC, legal_name ASC LIMIT ?"
        params.append(limit)

        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["risk_factors"] = json.loads(item.pop("risk_factors_json") or "{}")
            results.append(item)
        return results

    def get_beneficial_owners(self, customer_id: str) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM beneficial_owners WHERE customer_id = ? ORDER BY ownership_percentage DESC",
                (customer_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def update_risk_score(
        self,
        customer_id: str,
        composite_risk_score: float,
        risk_band: str,
        risk_factors: Dict[str, Any],
    ) -> Dict[str, Any]:
        now = _now_iso()
        factors_json = json.dumps(risk_factors, sort_keys=True)
        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE customers
                SET composite_risk_score = ?, risk_band = ?, risk_factors_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (round(composite_risk_score, 2), risk_band, factors_json, now, customer_id),
            )
        return self.get_by_id(customer_id)


class AccountRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def get_by_id(self, account_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        if not row:
            raise ResourceNotFoundError("Account", account_id)
        return dict(row)

    def list_by_customer(self, customer_id: str) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM accounts WHERE customer_id = ? ORDER BY opened_at ASC",
                (customer_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_all(self) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM accounts ORDER BY account_number ASC").fetchall()
        return [dict(r) for r in rows]


class TransactionRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def get_by_id(self, tx_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,)).fetchone()
        if not row:
            raise ResourceNotFoundError("Transaction", tx_id)
        return dict(row)

    def list_transactions(
        self,
        account_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        tx_type: Optional[str] = None,
        direction: Optional[str] = None,
        min_amount_usd: Optional[float] = None,
        is_flagged: Optional[int] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM transactions WHERE 1=1"
        params: List[Any] = []
        if account_id:
            query += " AND (account_id = ? OR counterparty_account_id = ?)"
            params.extend([account_id, account_id])
        if customer_id:
            query += " AND customer_id = ?"
            params.append(customer_id)
        if tx_type:
            query += " AND tx_type = ?"
            params.append(tx_type)
        if direction:
            query += " AND direction = ?"
            params.append(direction)
        if min_amount_usd is not None:
            query += " AND amount_usd >= ?"
            params.append(float(min_amount_usd))
        if is_flagged is not None:
            query += " AND is_flagged = ?"
            params.append(int(is_flagged))
        query += " ORDER BY tx_timestamp DESC LIMIT ?"
        params.append(limit)

        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def list_all_chronological(self) -> List[Dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute("SELECT * FROM transactions ORDER BY tx_timestamp ASC").fetchall()
        return [dict(r) for r in rows]

    def insert_transaction(self, tx_data: Dict[str, Any]) -> Dict[str, Any]:
        tx_id = tx_data.get("id") or f"tx-{uuid.uuid4().hex[:12]}"
        ext_id = tx_data.get("external_tx_id") or f"EXT-{uuid.uuid4().hex[:10].upper()}"
        now = _now_iso()
        ts = tx_data.get("tx_timestamp") or now
        amount_orig = float(tx_data["amount_original"])
        fx_rate = float(tx_data.get("fx_rate_to_usd", 1.0))
        amount_usd = round(float(tx_data.get("amount_usd", amount_orig * fx_rate)), 2)

        with self.db.connection() as conn:
            acct_row = conn.execute(
                "SELECT customer_id, current_balance_usd FROM accounts WHERE id = ?",
                (tx_data["account_id"],),
            ).fetchone()
            if not acct_row:
                raise ResourceNotFoundError("Account", tx_data["account_id"])
            customer_id = tx_data.get("customer_id") or acct_row["customer_id"]
            current_bal = float(acct_row["current_balance_usd"])
            new_bal = (
                round(current_bal + amount_usd, 2)
                if tx_data["direction"] == "INBOUND"
                else round(current_bal - amount_usd, 2)
            )

            conn.execute(
                """
                INSERT INTO transactions (
                    id, external_tx_id, account_id, customer_id, counterparty_id,
                    counterparty_account_id, tx_timestamp, tx_type, direction,
                    amount_original, currency_original, fx_rate_to_usd, amount_usd,
                    balance_after_usd, channel, origin_country, destination_country,
                    ip_address, device_fingerprint, geo_lat, geo_lon, mcc_code,
                    branch_or_atm_id, remittance_purpose, scenario_tag, is_flagged, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tx_id,
                    ext_id,
                    tx_data["account_id"],
                    customer_id,
                    tx_data.get("counterparty_id"),
                    tx_data.get("counterparty_account_id"),
                    ts,
                    tx_data["tx_type"],
                    tx_data["direction"],
                    amount_orig,
                    tx_data.get("currency_original", "USD"),
                    fx_rate,
                    amount_usd,
                    new_bal,
                    tx_data.get("channel", "ONLINE_WEB"),
                    tx_data.get("origin_country", "US"),
                    tx_data.get("destination_country", "US"),
                    tx_data.get("ip_address"),
                    tx_data.get("device_fingerprint"),
                    tx_data.get("geo_lat"),
                    tx_data.get("geo_lon"),
                    tx_data.get("mcc_code"),
                    tx_data.get("branch_or_atm_id"),
                    tx_data.get("remittance_purpose"),
                    tx_data.get("scenario_tag"),
                    int(tx_data.get("is_flagged", 0)),
                    now,
                ),
            )
            conn.execute(
                "UPDATE accounts SET current_balance_usd = ?, last_activity_at = ? WHERE id = ?",
                (new_bal, ts, tx_data["account_id"]),
            )
        return self.get_by_id(tx_id)


class RuleRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def list_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        query = "SELECT * FROM typology_rules"
        if enabled_only:
            query += " WHERE is_enabled = 1"
        query += " ORDER BY id ASC"
        with self.db.connection() as conn:
            rows = conn.execute(query).fetchall()
        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["parameters"] = json.loads(item.pop("parameters_json") or "{}")
            results.append(item)
        return results

    def get_rule(self, rule_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM typology_rules WHERE id = ?", (rule_id,)).fetchone()
        if not row:
            raise ResourceNotFoundError("TypologyRule", rule_id)
        item = dict(row)
        item["parameters"] = json.loads(item.pop("parameters_json") or "{}")
        return item

    def update_rule(
        self,
        rule_id: str,
        parameters: Dict[str, Any],
        is_enabled: bool,
        change_reason: str,
        actor_user_id: str,
    ) -> Dict[str, Any]:
        current = self.get_rule(rule_id)
        new_version = int(current["version"]) + 1
        now = _now_iso()
        params_json = json.dumps(parameters, sort_keys=True)

        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE typology_rules
                SET parameters_json = ?, is_enabled = ?, version = ?, updated_by = ?, updated_at = ?
                WHERE id = ?
                """,
                (params_json, 1 if is_enabled else 0, new_version, actor_user_id, now, rule_id),
            )
            conn.execute(
                """
                INSERT INTO rule_versions (
                    id, rule_id, version, parameters_json, is_enabled, change_reason, changed_by, changed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"rv-{uuid.uuid4().hex[:10]}",
                    rule_id,
                    new_version,
                    params_json,
                    1 if is_enabled else 0,
                    change_reason,
                    actor_user_id,
                    now,
                ),
            )
        return self.get_rule(rule_id)
