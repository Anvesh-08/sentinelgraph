"""
Alert Triage & Four-Eyes Case Investigation Lifecycle Service (`FR-CASE`).
Enforces strict state transitions and compliance controls:
- Valid Case Transitions:
  OPEN -> IN_REVIEW_L1, ESCALATED_L2, CLOSED_FALSE_POSITIVE, CLOSED_NO_SAR
  IN_REVIEW_L1 -> ESCALATED_L2, PENDING_QA_APPROVAL, CLOSED_FALSE_POSITIVE, CLOSED_NO_SAR
  ESCALATED_L2 -> PENDING_QA_APPROVAL, CLOSED_FALSE_POSITIVE, CLOSED_NO_SAR
  PENDING_QA_APPROVAL -> SAR_APPROVED, ESCALATED_L2 (rejected back to L2), CLOSED_NO_SAR
  SAR_APPROVED -> SAR_FILED
- Four-Eyes Separation of Duties:
  When transitioning from `PENDING_QA_APPROVAL` to `SAR_APPROVED` or `SAR_FILED`,
  the `actor_user_id` CANNOT equal the case's `investigator_id`.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from backend.app.audit.service import AuditService
from backend.app.core.exceptions import (
    ResourceNotFoundError,
    SeparationOfDutiesError,
    StateTransitionError,
    ValidationError,
)
from backend.app.db.connection import DatabaseManager


ALLOWED_CASE_TRANSITIONS: Dict[str, Set[str]] = {
    "OPEN": {"IN_REVIEW_L1", "ESCALATED_L2", "CLOSED_FALSE_POSITIVE", "CLOSED_NO_SAR"},
    "IN_REVIEW_L1": {"ESCALATED_L2", "PENDING_QA_APPROVAL", "CLOSED_FALSE_POSITIVE", "CLOSED_NO_SAR"},
    "ESCALATED_L2": {"PENDING_QA_APPROVAL", "CLOSED_FALSE_POSITIVE", "CLOSED_NO_SAR"},
    "PENDING_QA_APPROVAL": {"SAR_APPROVED", "ESCALATED_L2", "CLOSED_NO_SAR"},
    "SAR_APPROVED": {"SAR_FILED"},
    "SAR_FILED": set(),
    "CLOSED_FALSE_POSITIVE": {"IN_REVIEW_L1"},
    "CLOSED_NO_SAR": {"IN_REVIEW_L1"},
}


class CaseManagementService:
    """Coordinates alert triage, case promotion, investigator notes, and Four-Eyes QA approvals."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.audit = AuditService(db)

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT a.*, c.legal_name AS customer_name, c.risk_band AS customer_risk_band,
                       ac.account_number, r.name AS rule_name, r.family AS rule_family
                FROM alerts a
                JOIN customers c ON c.id = a.customer_id
                JOIN accounts ac ON ac.id = a.account_id
                JOIN typology_rules r ON r.id = a.rule_id
                WHERE a.id = ?
                """,
                (alert_id,),
            ).fetchone()
            if not row:
                raise ResourceNotFoundError("Alert", alert_id)
            tx_rows = conn.execute(
                """
                SELECT t.*
                FROM transactions t
                JOIN alert_transactions atx ON atx.transaction_id = t.id
                WHERE atx.alert_id = ?
                ORDER BY t.tx_timestamp ASC
                """,
                (alert_id,),
            ).fetchall()

        item = dict(row)
        item["evidence_metrics"] = json.loads(item.pop("evidence_metrics_json") or "{}")
        item["transactions"] = [dict(t) for t in tx_rows]
        return item

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        rule_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        limit: int = 300,
    ) -> List[Dict[str, Any]]:
        query = """
            SELECT a.*, c.legal_name AS customer_name, c.risk_band AS customer_risk_band,
                   ac.account_number, r.name AS rule_name, r.family AS rule_family
            FROM alerts a
            JOIN customers c ON c.id = a.customer_id
            JOIN accounts ac ON ac.id = a.account_id
            JOIN typology_rules r ON r.id = a.rule_id
            WHERE 1=1
        """
        params: List[Any] = []
        if status:
            query += " AND a.status = ?"
            params.append(status)
        if severity:
            query += " AND a.severity = ?"
            params.append(severity)
        if rule_id:
            query += " AND a.rule_id = ?"
            params.append(rule_id)
        if customer_id:
            query += " AND a.customer_id = ?"
            params.append(customer_id)
        query += " ORDER BY a.risk_score DESC, a.created_at DESC LIMIT ?"
        params.append(limit)

        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["evidence_metrics"] = json.loads(item.pop("evidence_metrics_json") or "{}")
            results.append(item)
        return results

    def triage_alert(
        self,
        alert_id: str,
        action: str,
        actor_user_id: str,
        actor_role: str,
        assigned_to_user_id: Optional[str] = None,
        disposition_reason: Optional[str] = None,
        case_title: Optional[str] = None,
        case_priority: str = "HIGH",
        existing_case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        alert = self.get_alert(alert_id)
        now = datetime.now(timezone.utc).isoformat()
        action = action.upper().strip()

        if action == "ASSIGN":
            target_user = assigned_to_user_id or actor_user_id
            with self.db.connection() as conn:
                conn.execute(
                    "UPDATE alerts SET status = 'IN_TRIAGE', assigned_to = ? WHERE id = ?",
                    (target_user, alert_id),
                )
            self.audit.record_event(
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                action="ALERT_ASSIGNED",
                entity_type="Alert",
                entity_id=alert_id,
                details={"assigned_to": target_user, "alert_ref": alert["alert_ref"]},
            )
            return self.get_alert(alert_id)

        if action == "DISMISS_FALSE_POSITIVE":
            if not disposition_reason or len(disposition_reason.strip()) < 10:
                raise ValidationError(
                    "Dismissing an alert as a false positive requires a substantive disposition_reason (min 10 chars)."
                )
            with self.db.connection() as conn:
                conn.execute(
                    """
                    UPDATE alerts
                    SET status = 'DISMISSED_FALSE_POSITIVE', disposition_reason = ?,
                        assigned_to = COALESCE(assigned_to, ?), resolved_at = ?
                    WHERE id = ?
                    """,
                    (disposition_reason.strip(), actor_user_id, now, alert_id),
                )
            self.audit.record_event(
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                action="ALERT_DISMISSED_FALSE_POSITIVE",
                entity_type="Alert",
                entity_id=alert_id,
                details={"reason": disposition_reason.strip(), "alert_ref": alert["alert_ref"]},
            )
            return self.get_alert(alert_id)

        if action == "ESCALATE_TO_CASE":
            suspicious_sum = round(sum(float(t["amount_usd"]) for t in alert["transactions"]), 2)
            with self.db.connection() as conn:
                if existing_case_id:
                    case_row = conn.execute("SELECT * FROM cases WHERE id = ?", (existing_case_id,)).fetchone()
                    if not case_row:
                        raise ResourceNotFoundError("Case", existing_case_id)
                    case_id = existing_case_id
                    tags = set(json.loads(case_row["typology_tags_json"] or "[]"))
                    tags.add(alert["rule_id"])
                    new_total = round(float(case_row["total_suspicious_amount_usd"]) + suspicious_sum, 2)
                    conn.execute(
                        """
                        UPDATE cases
                        SET total_suspicious_amount_usd = ?, typology_tags_json = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (new_total, json.dumps(sorted(tags)), now, case_id),
                    )
                else:
                    cnt_row = conn.execute("SELECT COUNT(*) AS cnt FROM cases").fetchone()
                    seq = (int(cnt_row["cnt"]) if cnt_row else 0) + 1
                    case_id = f"case-{uuid.uuid4().hex[:12]}"
                    case_number = f"CASE-2026-{seq:04d}"
                    title = case_title or f"{alert['rule_id']} Investigation — {alert['customer_name']}"
                    conn.execute(
                        """
                        INSERT INTO cases (
                            id, case_number, primary_customer_id, title, status, priority,
                            investigator_id, total_suspicious_amount_usd, typology_tags_json,
                            opened_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'IN_REVIEW_L1', ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case_id,
                            case_number,
                            alert["customer_id"],
                            title,
                            case_priority,
                            actor_user_id,
                            suspicious_sum,
                            json.dumps([alert["rule_id"]]),
                            now,
                            now,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO case_notes (
                            id, case_id, author_user_id, author_role, note_type, content, created_at
                        ) VALUES (?, ?, ?, ?, 'ESCALATION_MEMO', ?, ?)
                        """,
                        (
                            f"cn-{uuid.uuid4().hex[:12]}",
                            case_id,
                            actor_user_id,
                            actor_role,
                            f"Case opened from Alert {alert['alert_ref']} ({alert['rule_name']}). {alert['trigger_narrative']}",
                            now,
                        ),
                    )

                conn.execute(
                    """
                    UPDATE alerts
                    SET status = 'ESCALATED_TO_CASE', case_id = ?, assigned_to = COALESCE(assigned_to, ?), resolved_at = ?
                    WHERE id = ?
                    """,
                    (case_id, actor_user_id, now, alert_id),
                )

            self.audit.record_event(
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                action="ALERT_ESCALATED_TO_CASE",
                entity_type="Case",
                entity_id=case_id,
                details={"alert_id": alert_id, "alert_ref": alert["alert_ref"], "suspicious_usd": suspicious_sum},
            )
            return self.get_alert(alert_id)

        raise ValidationError(f"Unsupported alert triage action '{action}'.")

    def get_case(self, case_id: str) -> Dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute(
                """
                SELECT c.*, cu.legal_name AS customer_name, cu.external_ref AS customer_ref,
                       cu.risk_band AS customer_risk_band, cu.composite_risk_score AS customer_risk_score,
                       u1.full_name AS investigator_name, u2.full_name AS qa_reviewer_name
                FROM cases c
                JOIN customers cu ON cu.id = c.primary_customer_id
                LEFT JOIN users u1 ON u1.id = c.investigator_id
                LEFT JOIN users u2 ON u2.id = c.qa_reviewer_id
                WHERE c.id = ?
                """,
                (case_id,),
            ).fetchone()
            if not row:
                raise ResourceNotFoundError("Case", case_id)

            alert_rows = conn.execute(
                "SELECT * FROM alerts WHERE case_id = ? ORDER BY created_at ASC", (case_id,)
            ).fetchall()
            note_rows = conn.execute(
                """
                SELECT cn.*, u.full_name AS author_name
                FROM case_notes cn
                JOIN users u ON u.id = cn.author_user_id
                WHERE cn.case_id = ?
                ORDER BY cn.created_at ASC
                """,
                (case_id,),
            ).fetchall()
            sar_rows = conn.execute(
                "SELECT * FROM sar_reports WHERE case_id = ? ORDER BY created_at DESC", (case_id,)
            ).fetchall()
            tx_rows = conn.execute(
                """
                SELECT DISTINCT t.*
                FROM transactions t
                JOIN alert_transactions atx ON atx.transaction_id = t.id
                JOIN alerts a ON a.id = atx.alert_id
                WHERE a.case_id = ?
                ORDER BY t.tx_timestamp ASC
                """,
                (case_id,),
            ).fetchall()

        case_dict = dict(row)
        case_dict["typology_tags"] = json.loads(case_dict.pop("typology_tags_json") or "[]")
        case_dict["alerts"] = [
            {**dict(a), "evidence_metrics": json.loads(a["evidence_metrics_json"] or "{}")}
            for a in alert_rows
        ]
        for a in case_dict["alerts"]:
            a.pop("evidence_metrics_json", None)
        case_dict["notes"] = [dict(n) for n in note_rows]
        case_dict["sar_reports"] = [
            {**dict(s), "typology_codes": json.loads(s["typology_codes_json"] or "[]")}
            for s in sar_rows
        ]
        for s in case_dict["sar_reports"]:
            s.pop("typology_codes_json", None)
        case_dict["suspicious_transactions"] = [dict(t) for t in tx_rows]
        return case_dict

    def list_cases(self, status: Optional[str] = None, priority: Optional[str] = None) -> List[Dict[str, Any]]:
        query = """
            SELECT c.*, cu.legal_name AS customer_name, cu.risk_band AS customer_risk_band,
                   u1.full_name AS investigator_name, u2.full_name AS qa_reviewer_name
            FROM cases c
            JOIN customers cu ON cu.id = c.primary_customer_id
            LEFT JOIN users u1 ON u1.id = c.investigator_id
            LEFT JOIN users u2 ON u2.id = c.qa_reviewer_id
            WHERE 1=1
        """
        params: List[Any] = []
        if status:
            query += " AND c.status = ?"
            params.append(status)
        if priority:
            query += " AND c.priority = ?"
            params.append(priority)
        query += " ORDER BY c.updated_at DESC"

        with self.db.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        results: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["typology_tags"] = json.loads(item.pop("typology_tags_json") or "[]")
            results.append(item)
        return results

    def add_case_note(
        self,
        case_id: str,
        author_user_id: str,
        author_role: str,
        content: str,
        note_type: str = "INVESTIGATION_NOTE",
        attachment_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        _ = self.get_case(case_id)
        now = datetime.now(timezone.utc).isoformat()
        note_id = f"cn-{uuid.uuid4().hex[:12]}"
        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO case_notes (
                    id, case_id, author_user_id, author_role, note_type, content, attachment_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (note_id, case_id, author_user_id, author_role, note_type, content.strip(), attachment_hash, now),
            )
            conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))

        self.audit.record_event(
            actor_user_id=author_user_id,
            actor_role=author_role,
            action="CASE_NOTE_ADDED",
            entity_type="Case",
            entity_id=case_id,
            details={"note_id": note_id, "note_type": note_type},
        )
        return self.get_case(case_id)

    def transition_case_status(
        self,
        case_id: str,
        target_status: str,
        actor_user_id: str,
        actor_role: str,
        notes: str,
        disposition_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        case_obj = self.get_case(case_id)
        current_status = case_obj["status"]
        target_status = target_status.upper().strip()

        allowed = ALLOWED_CASE_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            raise StateTransitionError(
                entity_type="Case",
                current_state=current_status,
                target_state=target_status,
                reason=f"Allowed transitions from '{current_status}': {sorted(allowed)}",
            )

        # Enforce Four-Eyes Separation of Duties on QA Approval & SAR Filing
        if target_status in ("SAR_APPROVED", "SAR_FILED"):
            if actor_role not in ("QA_COMPLIANCE_OFFICER", "SYSTEM_ADMIN"):
                raise SeparationOfDutiesError(
                    f"Role '{actor_role}' cannot approve or file SARs; QA_COMPLIANCE_OFFICER required."
                )
            if case_obj.get("investigator_id") and case_obj["investigator_id"] == actor_user_id:
                raise SeparationOfDutiesError(
                    "Four-Eyes Separation of Duties Violation: Investigator who prepared/escalated the case "
                    f"('{actor_user_id}') cannot QA-approve their own investigation."
                )
            if not case_obj.get("sar_reports"):
                raise ValidationError(
                    "Cannot transition case to SAR_APPROVED or SAR_FILED before generating a FinCEN SAR report."
                )

        now = datetime.now(timezone.utc).isoformat()
        qa_submitted_at = now if target_status == "PENDING_QA_APPROVAL" else case_obj.get("qa_submitted_at")
        closed_at = (
            now
            if target_status in ("SAR_FILED", "CLOSED_FALSE_POSITIVE", "CLOSED_NO_SAR")
            else case_obj.get("closed_at")
        )
        qa_reviewer_id = (
            actor_user_id
            if target_status in ("SAR_APPROVED", "SAR_FILED")
            else case_obj.get("qa_reviewer_id")
        )
        investigator_id = (
            actor_user_id
            if target_status in ("IN_REVIEW_L1", "ESCALATED_L2", "PENDING_QA_APPROVAL") and not case_obj.get("investigator_id")
            else case_obj.get("investigator_id")
        )

        with self.db.connection() as conn:
            conn.execute(
                """
                UPDATE cases
                SET status = ?, investigator_id = ?, qa_reviewer_id = ?,
                    disposition_summary = COALESCE(?, disposition_summary),
                    qa_decision_notes = CASE WHEN ? IN ('SAR_APPROVED', 'SAR_FILED') THEN ? ELSE qa_decision_notes END,
                    qa_submitted_at = ?, closed_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    target_status,
                    investigator_id,
                    qa_reviewer_id,
                    disposition_summary,
                    target_status,
                    notes,
                    qa_submitted_at,
                    closed_at,
                    now,
                    case_id,
                ),
            )
            conn.execute(
                """
                INSERT INTO case_notes (
                    id, case_id, author_user_id, author_role, note_type, content, created_at
                ) VALUES (?, ?, ?, ?, 'SYSTEM_EVENT', ?, ?)
                """,
                (
                    f"cn-{uuid.uuid4().hex[:12]}",
                    case_id,
                    actor_user_id,
                    actor_role,
                    f"State transition [{current_status} -> {target_status}]: {notes}",
                    now,
                ),
            )
            if target_status == "SAR_APPROVED":
                conn.execute(
                    "UPDATE sar_reports SET filing_status = 'APPROVED', approved_by = ? WHERE case_id = ?",
                    (actor_user_id, case_id),
                )
            elif target_status == "SAR_FILED":
                bsa_id = f"BSA-FINCEN-2026-{uuid.uuid4().hex[:8].upper()}"
                conn.execute(
                    """
                    UPDATE sar_reports
                    SET filing_status = 'FILED_WITH_FINCEN', approved_by = COALESCE(approved_by, ?),
                        fincen_bsa_id = COALESCE(fincen_bsa_id, ?), filed_at = ?
                    WHERE case_id = ?
                    """,
                    (actor_user_id, bsa_id, now, case_id),
                )

        self.audit.record_event(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action="CASE_STATUS_TRANSITION",
            entity_type="Case",
            entity_id=case_id,
            details={"from_status": current_status, "to_status": target_status, "notes": notes},
        )
        return self.get_case(case_id)
