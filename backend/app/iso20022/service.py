"""
ISO 20022 MX & SWIFT MT Wire Ingestion Service.
Parses raw XML or SWIFT FIN payloads, executes Travel Rule & Wire-Stripping compliance audits,
persists normalized transactions into the SentinelGraph ledger, and triggers real-time typology evaluation.
"""
from typing import Any, Dict, List, Optional

from backend.app.audit.service import AuditService
from backend.app.db.connection import DatabaseManager
from backend.app.iso20022.models import ParsedWireTransferMessage
from backend.app.iso20022.mx_parser import Iso20022MxParser
from backend.app.iso20022.swift_mt_parser import SwiftMtParser
from backend.app.repositories.core_repositories import TransactionRepository
from backend.app.typologies.engine import TypologyEngine


class WireMessageIngestionService:
    """Ingests ISO 20022 XML and SWIFT MT103/MT202 messages into the transaction monitoring pipeline."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.tx_repo = TransactionRepository(db)
        self.typology_engine = TypologyEngine(db)
        self.audit = AuditService(db)

    def ingest_iso20022_xml(
        self,
        xml_payload: str,
        target_internal_account_id: str,
        direction: str = "OUTBOUND",
        actor_user_id: str = "usr-eng",
        actor_role: str = "RISK_ENGINEER",
        evaluate_rules: bool = True,
    ) -> Dict[str, Any]:
        parsed_messages = Iso20022MxParser.parse_xml(xml_payload)
        return self._persist_parsed_messages(
            parsed_messages=parsed_messages,
            target_internal_account_id=target_internal_account_id,
            direction=direction,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            evaluate_rules=evaluate_rules,
        )

    def ingest_swift_mt(
        self,
        mt_payload: str,
        target_internal_account_id: str,
        direction: str = "OUTBOUND",
        actor_user_id: str = "usr-eng",
        actor_role: str = "RISK_ENGINEER",
        evaluate_rules: bool = True,
    ) -> Dict[str, Any]:
        parsed = SwiftMtParser.parse_mt_message(mt_payload)
        return self._persist_parsed_messages(
            parsed_messages=[parsed],
            target_internal_account_id=target_internal_account_id,
            direction=direction,
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            evaluate_rules=evaluate_rules,
        )

    def _persist_parsed_messages(
        self,
        parsed_messages: List[ParsedWireTransferMessage],
        target_internal_account_id: str,
        direction: str,
        actor_user_id: str,
        actor_role: str,
        evaluate_rules: bool,
    ) -> Dict[str, Any]:
        ingested_txs: List[Dict[str, Any]] = []
        travel_rule_audits: List[Dict[str, Any]] = []

        for msg in parsed_messages:
            tx_payload = msg.to_sentinelgraph_tx_payload(
                internal_account_id=target_internal_account_id,
                direction=direction,
            )
            inserted = self.tx_repo.insert_transaction(tx_payload)
            ingested_txs.append(inserted)
            if msg.travel_rule_audit:
                travel_rule_audits.append(
                    {
                        "message_id": msg.message_id,
                        "standard": msg.message_standard,
                        "transaction_id": inserted["id"],
                        **msg.travel_rule_audit.to_dict(),
                    }
                )

        eval_summary: Optional[Dict[str, Any]] = None
        if evaluate_rules:
            eval_summary = self.typology_engine.evaluate_all_rules(persist_alerts=True)

        self.audit.record_event(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action="WIRE_MESSAGE_BATCH_INGESTED",
            entity_type="Account",
            entity_id=target_internal_account_id,
            details={
                "messages_parsed": len(parsed_messages),
                "standards": [m.message_standard for m in parsed_messages],
                "non_compliant_travel_rule_count": sum(1 for a in travel_rule_audits if not a["is_compliant"]),
            },
        )

        return {
            "messages_parsed": len(parsed_messages),
            "ingested_transactions": ingested_txs,
            "travel_rule_audits": travel_rule_audits,
            "typology_evaluation": eval_summary,
        }
