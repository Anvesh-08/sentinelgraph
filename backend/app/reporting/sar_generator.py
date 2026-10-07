"""
FinCEN Suspicious Activity Report (SAR) 5-W Narrative Builder (`FR-CASE-04`).
Synthesizes Subject KYC/KYB profiles, Beneficial Ownership, Triggered Typology Rules,
Transaction Timelines, Geographic Corridors, and Graph Forensics into a structured,
regulator-ready FinCEN SAR narrative covering:
1. WHO is conducting the suspicious activity?
2. WHAT instruments or mechanisms are being used?
3. WHEN did the suspicious activity occur?
4. WHERE did the suspicious activity take place?
5. WHY does the filer think the activity is suspicious & HOW was it executed?
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.audit.service import AuditService
from backend.app.cases.service import CaseManagementService
from backend.app.core.exceptions import ValidationError
from backend.app.db.connection import DatabaseManager
from backend.app.repositories.core_repositories import CustomerRepository


class FinCENSarGenerator:
    """Builds, validates, and persists structured FinCEN 5-W Suspicious Activity Reports."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.case_service = CaseManagementService(db)
        self.customer_repo = CustomerRepository(db)
        self.audit = AuditService(db)

    def generate_sar_for_case(
        self,
        case_id: str,
        prepared_by_user_id: str,
        prepared_by_role: str,
        filing_type: str = "INITIAL",
        custom_why_how_addendum: Optional[str] = None,
        auto_submit_for_qa: bool = False,
    ) -> Dict[str, Any]:
        case_obj = self.case_service.get_case(case_id)
        customer = self.customer_repo.get_by_id(case_obj["primary_customer_id"])
        ubos = self.customer_repo.get_beneficial_owners(customer["id"])
        txs = case_obj.get("suspicious_transactions", [])
        alerts = case_obj.get("alerts", [])

        if not txs:
            # Fallback to customer's flagged transactions if alert_transactions was empty
            with self.db.connection() as conn:
                tx_rows = conn.execute(
                    "SELECT * FROM transactions WHERE customer_id = ? ORDER BY tx_timestamp ASC",
                    (customer["id"],),
                ).fetchall()
                txs = [dict(r) for r in tx_rows]

        if not txs:
            raise ValidationError("Cannot generate a FinCEN SAR for a case with zero linked transactions.")

        start_date = txs[0]["tx_timestamp"][:10]
        end_date = txs[-1]["tx_timestamp"][:10]
        total_usd = round(sum(float(t["amount_usd"]) for t in txs), 2)
        typology_codes = sorted({a["rule_id"] for a in alerts} | set(case_obj.get("typology_tags", [])))

        # 1. WHO Section
        ubo_text = (
            "; ".join(
                f"{u['full_name']} ({u['ownership_percentage']:.0f}% ownership, Nationality: {u['nationality']}, PEP: {'Yes' if u['is_pep'] else 'No'})"
                for u in ubos
            )
            if ubos
            else "No separate beneficial owners recorded (Individual retail account)."
        )
        narrative_who = (
            f"SUBJECT IDENTIFICATION (WHO): The primary subject of this report is {customer['legal_name']} "
            f"(External CIF Reference: {customer['external_ref']}), a {customer['customer_type']} customer "
            f"onboarded on {customer['onboarding_date']} in the '{customer['occupation_or_industry']}' sector. "
            f"The subject holds nationality/registration in {customer['nationality_or_reg_country']} and resides in "
            f"{customer['residence_country']}. At the time of review, the subject's SentinelGraph Composite Risk Score "
            f"is {customer['composite_risk_score']:.2f}/100 ({customer['risk_band']} Risk Band), with PEP Status: "
            f"{'YES' if customer['pep_flag'] else 'NO'}, Sanctions Status: {customer['sanctions_status']}, and "
            f"Stated Expected Monthly Volume: ${float(customer['expected_monthly_volume_usd']):,.2f} USD. "
            f"Beneficial Ownership Details: {ubo_text}"
        )

        # 2. WHAT Section
        tx_types = sorted({t["tx_type"] for t in txs})
        channels = sorted({t["channel"] for t in txs})
        inbound_sum = round(sum(float(t["amount_usd"]) for t in txs if t["direction"] == "INBOUND"), 2)
        outbound_sum = round(sum(float(t["amount_usd"]) for t in txs if t["direction"] == "OUTBOUND"), 2)
        narrative_what = (
            f"INSTRUMENTS & FINANCIAL MECHANISMS (WHAT): This filing covers {len(txs)} suspicious transaction(s) "
            f"aggregating ${total_usd:,.2f} USD (${inbound_sum:,.2f} inbound credits and ${outbound_sum:,.2f} outbound debits). "
            f"The activity utilized payment instruments [{', '.join(tx_types)}] across execution channels [{', '.join(channels)}]."
        )

        # 3. WHEN Section
        tx_lines = [
            f"- {t['tx_timestamp']}: {t['external_tx_id']} | {t['direction']} {t['tx_type']} | ${float(t['amount_usd']):,.2f} USD ({t['origin_country']} -> {t['destination_country']})"
            for t in txs[:12]
        ]
        narrative_when = (
            f"ACTIVITY TIMELINE & VELOCITY (WHEN): The suspicious activity occurred between {start_date} and {end_date}. "
            f"Chronological breakdown of primary flagged transactions:\n" + "\n".join(tx_lines)
        )

        # 4. WHERE Section
        countries = sorted({t["origin_country"] for t in txs} | {t["destination_country"] for t in txs})
        devices = sorted({t["device_fingerprint"] for t in txs if t.get("device_fingerprint")})
        ips = sorted({t["ip_address"] for t in txs if t.get("ip_address")})
        terminals = sorted({t["branch_or_atm_id"] for t in txs if t.get("branch_or_atm_id")})
        narrative_where = (
            f"GEOGRAPHIC & TECHNICAL FOOTPRINT (WHERE): Activity spanned jurisdictions [{', '.join(countries)}]. "
            f"Physical Branch/ATM Terminals utilized: {', '.join(terminals) if terminals else 'N/A (Digital Channels)'}. "
            f"Captured Device Fingerprints: {', '.join(devices) if devices else 'None'}. "
            f"Captured IP Addresses: {', '.join(ips) if ips else 'None'}."
        )

        # 5. WHY & HOW Section
        alert_summaries = [
            f"[{a['rule_id']} - {a['rule_name']}]: {a['trigger_narrative']}"
            for a in alerts
        ]
        narrative_why_how = (
            f"TYPOLOGY MECHANICS & RATIONALE FOR SUSPICION (WHY & HOW): Automated and forensic review under Case "
            f"{case_obj['case_number']} triggered typology rule(s) {', '.join(typology_codes)}. "
            + " ".join(alert_summaries)
            + f" The observed transaction volume of ${total_usd:,.2f} deviates materially from the customer's stated "
            f"KYC profile (${float(customer['expected_monthly_volume_usd']):,.2f}/month) and exhibits no verifiable "
            f"lawful commercial or personal economic purpose."
        )
        if custom_why_how_addendum:
            narrative_why_how += f"\n\nINVESTIGATOR FORENSIC ADDENDUM: {custom_why_how_addendum.strip()}"

        full_narrative = (
            f"FINCEN SUSPICIOUS ACTIVITY REPORT (SAR) NARRATIVE — CASE {case_obj['case_number']}\n"
            f"========================================================================\n\n"
            f"1. {narrative_who}\n\n"
            f"2. {narrative_what}\n\n"
            f"3. {narrative_when}\n\n"
            f"4. {narrative_where}\n\n"
            f"5. {narrative_why_how}\n"
        )
        content_sha256 = hashlib.sha256(full_narrative.encode("utf-8")).hexdigest()
        now_iso = datetime.now(timezone.utc).isoformat()

        with self.db.connection() as conn:
            cnt_row = conn.execute("SELECT COUNT(*) AS cnt FROM sar_reports").fetchone()
            seq = (int(cnt_row["cnt"]) if cnt_row else 0) + 1
            sar_id = f"sar-{uuid.uuid4().hex[:12]}"
            sar_ref = f"SAR-2026-{seq:05d}"
            status = "READY_FOR_QA" if auto_submit_for_qa else "DRAFT"

            conn.execute(
                """
                INSERT INTO sar_reports (
                    id, sar_ref, case_id, subject_customer_id, filing_type,
                    activity_start_date, activity_end_date, total_suspicious_amount_usd,
                    typology_codes_json, narrative_who, narrative_what, narrative_when,
                    narrative_where, narrative_why_how, full_narrative_text,
                    prepared_by, filing_status, content_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sar_id,
                    sar_ref,
                    case_id,
                    customer["id"],
                    filing_type,
                    start_date,
                    end_date,
                    total_usd,
                    json.dumps(typology_codes),
                    narrative_who,
                    narrative_what,
                    narrative_when,
                    narrative_where,
                    narrative_why_how,
                    full_narrative,
                    prepared_by_user_id,
                    status,
                    content_sha256,
                    now_iso,
                ),
            )

        self.audit.record_event(
            actor_user_id=prepared_by_user_id,
            actor_role=prepared_by_role,
            action="SAR_REPORT_GENERATED",
            entity_type="SARReport",
            entity_id=sar_id,
            details={
                "sar_ref": sar_ref,
                "case_id": case_id,
                "total_suspicious_amount_usd": total_usd,
                "content_sha256": content_sha256,
            },
        )

        if auto_submit_for_qa and case_obj["status"] in ("OPEN", "IN_REVIEW_L1", "ESCALATED_L2"):
            if case_obj["status"] == "OPEN":
                self.case_service.transition_case_status(
                    case_id=case_id,
                    target_status="ESCALATED_L2",
                    actor_user_id=prepared_by_user_id,
                    actor_role=prepared_by_role,
                    notes="Escalating to L2 prior to QA SAR submission.",
                )
            self.case_service.transition_case_status(
                case_id=case_id,
                target_status="PENDING_QA_APPROVAL",
                actor_user_id=prepared_by_user_id,
                actor_role=prepared_by_role,
                notes=f"Submitted FinCEN SAR {sar_ref} (SHA-256: {content_sha256[:12]}) for Four-Eyes QA review.",
            )

        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM sar_reports WHERE id = ?", (sar_id,)).fetchone()
        res = dict(row)
        res["typology_codes"] = json.loads(res.pop("typology_codes_json") or "[]")
        return res
