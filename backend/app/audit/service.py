"""
Tamper-evident cryptographic audit ledger service.
Every state-mutating action is recorded with an HMAC-SHA256 hash chain linked to the
previous audit record so any historical tampering or row deletion is immediately detectable.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.core.config import settings
from backend.app.core.exceptions import AuditIntegrityError
from backend.app.db.connection import DatabaseManager


GENESIS_PREVIOUS_HASH = "GENESIS_00000000000000000000000000000000000000000000000000000000"


class AuditService:
    """Manages immutable hash-chained audit logs and performs full-chain integrity verification."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    @staticmethod
    def compute_entry_hash(
        previous_hash: str,
        timestamp: str,
        actor_user_id: str,
        actor_role: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details_json: str,
    ) -> str:
        """Computes HMAC-SHA256 over the canonical pipe-delimited audit record fields."""
        canonical = (
            f"{previous_hash}|{timestamp}|{actor_user_id}|{actor_role}|"
            f"{action}|{entity_type}|{entity_id}|{details_json}"
        )
        return hmac.new(
            settings.audit_hmac_key.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def record_event(
        self,
        actor_user_id: str,
        actor_role: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Appends a new cryptographically signed entry to the audit ledger."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        canonical_details = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))

        with self.db.connection() as conn:
            last_row = conn.execute(
                "SELECT sequence_id, entry_hash FROM audit_logs ORDER BY sequence_id DESC LIMIT 1"
            ).fetchone()
            previous_hash = last_row["entry_hash"] if last_row else GENESIS_PREVIOUS_HASH

            entry_hash = self.compute_entry_hash(
                previous_hash=previous_hash,
                timestamp=ts,
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details_json=canonical_details,
            )

            cursor = conn.execute(
                """
                INSERT INTO audit_logs (
                    timestamp, actor_user_id, actor_role, action,
                    entity_type, entity_id, details_json, previous_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    actor_user_id,
                    actor_role,
                    action,
                    entity_type,
                    entity_id,
                    canonical_details,
                    previous_hash,
                    entry_hash,
                ),
            )
            seq_id = cursor.lastrowid

        return {
            "sequence_id": seq_id,
            "timestamp": ts,
            "actor_user_id": actor_user_id,
            "actor_role": actor_role,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details or {},
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
        }

    def verify_chain_integrity(self, raise_on_error: bool = False) -> Dict[str, Any]:
        """
        Walks the entire audit_logs table from genesis to tip, verifying:
        1. Contiguous sequence IDs (no deleted intermediate records).
        2. Each row's previous_hash matches the prior row's entry_hash.
        3. Each row's recomputed HMAC-SHA256 matches its stored entry_hash.
        """
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT sequence_id, timestamp, actor_user_id, actor_role, action,
                       entity_type, entity_id, details_json, previous_hash, entry_hash
                FROM audit_logs
                ORDER BY sequence_id ASC
                """
            ).fetchall()

        expected_prev_hash = GENESIS_PREVIOUS_HASH
        expected_seq_id = 1
        corrupted_entries: List[Dict[str, Any]] = []

        for row in rows:
            seq_id = int(row["sequence_id"])
            if seq_id != expected_seq_id:
                corrupted_entries.append(
                    {
                        "sequence_id": seq_id,
                        "reason": f"Sequence gap detected: expected sequence_id {expected_seq_id}, found {seq_id}.",
                    }
                )
                expected_seq_id = seq_id

            if row["previous_hash"] != expected_prev_hash:
                corrupted_entries.append(
                    {
                        "sequence_id": seq_id,
                        "reason": "Broken previous_hash link.",
                        "expected_previous_hash": expected_prev_hash,
                        "actual_previous_hash": row["previous_hash"],
                    }
                )

            recomputed = self.compute_entry_hash(
                previous_hash=row["previous_hash"],
                timestamp=row["timestamp"],
                actor_user_id=row["actor_user_id"],
                actor_role=row["actor_role"],
                action=row["action"],
                entity_type=row["entity_type"],
                entity_id=row["entity_id"],
                details_json=row["details_json"],
            )
            if not hmac.compare_digest(recomputed, row["entry_hash"]):
                corrupted_entries.append(
                    {
                        "sequence_id": seq_id,
                        "reason": "Entry HMAC-SHA256 digest mismatch (payload tampered).",
                        "expected_entry_hash": recomputed,
                        "actual_entry_hash": row["entry_hash"],
                    }
                )

            expected_prev_hash = row["entry_hash"]
            expected_seq_id += 1

        is_valid = len(corrupted_entries) == 0
        result = {
            "is_valid": is_valid,
            "total_records_verified": len(rows),
            "genesis_hash": GENESIS_PREVIOUS_HASH,
            "latest_tip_hash": expected_prev_hash if rows else GENESIS_PREVIOUS_HASH,
            "corrupted_entries": corrupted_entries,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
        if not is_valid and raise_on_error:
            raise AuditIntegrityError("Cryptographic audit log chain verification failed.", details=result)
        return result

    def list_logs(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        actor_user_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT sequence_id, timestamp, actor_user_id, actor_role, action,
                   entity_type, entity_id, details_json, previous_hash, entry_hash
            FROM audit_logs
            WHERE 1=1
        """
        params: List[Any] = []
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        if actor_user_id:
            query += " AND actor_user_id = ?"
            params.append(actor_user_id)
        query += " ORDER BY sequence_id DESC LIMIT ?"
        params.append(limit)

        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item.pop("details_json") or "{}")
            results.append(item)
        return results
