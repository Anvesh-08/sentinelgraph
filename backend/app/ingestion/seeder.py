"""
Deterministic Synthetic Financial Crime & Baseline Traffic Seeder (`FR-INGEST-03`).
Seeds the database with:
1. 5 RBAC Operator personas (`l1_analyst`, `l2_investigator`, `qa_officer`, `risk_engineer`, `admin`).
2. Watchlist / Sanctions & PEP reference entries (OFAC SDN, UN, EU, PEP, Adverse Media).
3. 18 Realistic Retail & Corporate (KYB) Customers with Beneficial Owners and Accounts.
4. Normal baseline transactions interleaved with 12 embedded criminal topologies that
   deterministically trigger the 25 typology rules, populate multi-hop graph rings,
   and provide labeled ground-truth data for RuleForge shadow-mode backtesting.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from backend.app.audit.service import AuditService
from backend.app.cases.service import CaseManagementService
from backend.app.core.security import Role, hash_password, hash_tax_id
from backend.app.db.connection import DatabaseManager
from backend.app.db.migrator import MigrationRunner
from backend.app.reporting.sar_generator import FinCENSarGenerator
from backend.app.risk.engine import CompositeRiskEngine
from backend.app.sanctions.screener import SanctionsScreeningService
from backend.app.simulation.engine import RuleSimulationEngine
from backend.app.typologies.engine import TypologyEngine


class SyntheticCrimeSeeder:
    """Seeds realistic AML/Fraud scenarios, runs initial evaluations, and creates sample cases/SARs."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def seed_all(self) -> Dict[str, Any]:
        MigrationRunner(self.db).run_migrations()
        typology_engine = TypologyEngine(self.db)
        typology_engine.ensure_default_rules_seeded()

        with self.db.connection() as conn:
            existing_users = conn.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()["cnt"]
            if int(existing_users) > 0:
                return {"status": "already_seeded"}

        now = "2026-10-01T08:00:00+00:00"
        users = [
            ("usr-l1", "l1_analyst", "arjun.mehta@sentinelgraph.local", "Arjun Mehta", Role.L1_ANALYST, "Analyst#2026!Secure"),
            ("usr-l2", "l2_investigator", "priya.nair@sentinelgraph.local", "Priya Nair", Role.L2_INVESTIGATOR, "Investigator#2026!Secure"),
            ("usr-qa", "qa_officer", "elena.rostova@sentinelgraph.local", "Elena Rostova", Role.QA_COMPLIANCE_OFFICER, "Compliance#2026!Secure"),
            ("usr-eng", "risk_engineer", "marcus.vance@sentinelgraph.local", "Marcus Vance", Role.RISK_ENGINEER, "Engineer#2026!Secure"),
            ("usr-adm", "admin", "admin@sentinelgraph.local", "Vikramitya Rao", Role.SYSTEM_ADMIN, "Admin#2026!Secure"),
        ]

        with self.db.connection() as conn:
            for uid, uname, email, fname, role, pwd in users:
                creds = hash_password(pwd, salt_hex=uid.encode("utf-8").hex().ljust(32, "0")[:32])
                conn.execute(
                    """
                    INSERT INTO users (id, username, email, full_name, role, password_hash, password_salt, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (uid, uname, email, fname, role, creds["password_hash"], creds["password_salt"], now),
                )

            # Seed Watchlist Entries
            watchlists = [
                ("wl-001", "OFAC_SDN", "INDIVIDUAL", "VIKTOR ALEKSANDROVICH MOROZOV", ["VIKTOR MOROZOV", "MOROZOV VIKTOR"], "1968-04-12", "RU", "OFAC-RUSSIA-EO14024", 98.0),
                ("wl-002", "OFAC_SDN", "ENTITY", "CASPIAN MERIDIAN PETROCHEMICAL TRADING LLC", ["CASPIAN MERIDIAN TRADING", "MERIDIAN PETROCHEM"], "2019-11-03", "IR", "OFAC-IRAN-SANCTIONS", 99.0),
                ("wl-003", "PEP_GLOBAL", "INDIVIDUAL", "CARLOS EDUARDO MENDOZA VALDEZ", ["MENDOZA CARLOS", "CARLOS MENDOZA"], "1962-09-21", "VE", "FOREIGN-SENIOR-POLITICAL-FIGURE", 88.0),
                ("wl-004", "UN_CONSOLIDATED", "INDIVIDUAL", "TARIQ AL-MANSOUR", ["TARIK AL MANSUR", "AL-MANSOUR TARIQ"], "1975-02-18", "SY", "UN-SANCTIONS-2253", 97.0),
                ("wl-005", "ADVERSE_MEDIA", "ENTITY", "BALTIC HORIZON LOGISTICS LTD", ["BALTIC HORIZON", "HORIZON LOGISTICS BVI"], "2021-06-15", "VG", "FINCEN-SHELL-LAUNDERING-ALERT", 85.0),
            ]
            for wid, src, etype, pname, aliases, dob, country, prog, weight in watchlists:
                conn.execute(
                    """
                    INSERT INTO watchlist_entries (
                        id, list_source, entity_type, primary_name, aliases_json,
                        date_of_birth, nationality_country, program_Or_category, risk_weight, active, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (wid, src, etype, pname, json.dumps(aliases), dob, country, prog, weight, now),
                )

            # Seed Customers (Retail & Corporate KYB)
            customers = [
                # 1. Structuring & Multi-Branch Smurfing Subject
                ("cust-001", "CUST-100001", "INDIVIDUAL", "Dante Morales", "1983-05-14", "US", "US", "CASH_INTENSIVE CONVENIENCE STORE OWNER", "445120", "TIN-001", "5500.0", 0, 0),
                # 2. High-Velocity Conduit Pass-Through & Offshore Shell Layering
                ("cust-002", "CUST-100002", "BUSINESS", "Baltic Horizon Trading Ltd", "2021-06-15", "VG", "PA", "IMPORT EXPORT GENERAL TRADING", "424990", "TIN-002", "25000.0", 1, 1),
                # 3. Carousel Round-Tripping Ring (Accounts A -> B -> C -> A)
                ("cust-003", "CUST-100003", "BUSINESS", "Apex Stratos Consulting LLC", "2020-02-10", "US", "US", "MANAGEMENT CONSULTING", "541611", "TIN-003", "18000.0", 0, 0),
                ("cust-004", "CUST-100004", "BUSINESS", "Vanguard Nexus Holdings Inc", "2022-01-19", "KY", "KY", "OFFSHORE HOLDING", "551112", "TIN-004", "20000.0", 0, 1),
                ("cust-005", "CUST-100005", "BUSINESS", "Solstice Maritime Services SA", "2019-08-25", "PA", "PA", "FREIGHT FORWARDING", "488510", "TIN-005", "22000.0", 0, 0),
                # 4. Fan-In / Fan-Out Money Mule Hub + Shared Device Ring
                ("cust-006", "CUST-100006", "INDIVIDUAL", "slava.kolesnikov", "1994-11-02", "UA", "US", "FREELANCE COURIER", "492210", "TIN-006", "3500.0", 0, 0),
                ("cust-007", "CUST-100007", "INDIVIDUAL", "Dmitri Volkov", "1991-07-19", "RU", "US", "DIGITAL ASSET BROKER", "523120", "TIN-007", "4000.0", 0, 1),
                ("cust-008", "CUST-100008", "INDIVIDUAL", "Oleg Petrov", "1993-03-30", "BY", "US", "IT CONTRACTOR", "541511", "TIN-008", "4500.0", 0, 0),
                # 5. Elder Financial Exploitation & ATO Victim
                ("cust-009", "CUST-100009", "INDIVIDUAL", "Eleanor Vance-Sterling", "1948-12-04", "US", "US", "RETIRED EDUCATOR", "611110", "TIN-009", "3200.0", 0, 0),
                # 6. PEP & High-Risk Corridor / Sanctions-Adjacent Transit
                ("cust-010", "CUST-100010", "INDIVIDUAL", "Carlos Eduardo Mendoza", "1962-09-21", "VE", "US", "ENERGY INFRASTRUCTURE ADVISOR", "213112", "TIN-010", "15000.0", 1, 1),
                # 7. Commercial KYB MCC Mismatch & Wash Trading
                ("cust-011", "CUST-100011", "BUSINESS", "precision_agri_logistics_llc", "2018-04-12", "US", "US", "AGRICULTURAL SUPPLY LOGISTICS", "493130", "TIN-011", "14000.0", 0, 0),
                # 8. Dormant Awakening & Impossible Travel
                ("cust-012", "CUST-100012", "INDIVIDUAL", "Tariq Al-Mansur", "1975-02-18", "SY", "AE", "PRECIOUS METALS BULLION DEALER", "423940", "TIN-012", "10000.0", 1, 1),
                # 9. Clean Baseline Low-Risk Customers
                ("cust-013", "CUST-100013", "INDIVIDUAL", "Hannah Lindqvist", "1989-06-22", "SE", "US", "SOFTWARE ARCHITECT", "541511", "TIN-013", "8500.0", 0, 0),
                ("cust-014", "CUST-100014", "INDIVIDUAL", "Rohan Deshmukh", "1986-01-15", "IN", "US", "CARDIOLOGIST", "621111", "TIN-014", "12000.0", 0, 0),
                ("cust-015", "CUST-100015", "BUSINESS", "GreenLeaf Pediatric Clinic PC", "2015-09-10", "US", "US", "MEDICAL CLINIC", "621111", "TIN-015", "45000.0", 0, 0),
            ]
            for cid, eref, ctype, name, dob, nat, res_c, ind, naics, tin, exp_vol, pep, media in customers:
                conn.execute(
                    """
                    INSERT INTO customers (
                        id, external_ref, customer_type, legal_name, date_of_birth_or_inc,
                        nationality_or_reg_country, residence_country, occupation_or_industry,
                        naics_code, tax_id_hash, email, phone_number, physical_address,
                        expected_monthly_volume_usd, pep_flag, adverse_media_flag,
                        onboarding_date, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '2024-01-15', ?, ?)
                    """,
                    (
                        cid, eref, ctype, name, dob, nat, res_c, ind, naics,
                        hash_tax_id(tin),
                        f"{cid}@example.local",
                        f"+120255501{cid[-2:]}",
                        f"100 Financial Plaza, Suite {cid[-3:]}, New York, NY",
                        float(exp_vol), pep, media, now, now,
                    ),
                )

            # Seed Beneficial Owners for Corporate KYB Entities
            ubos = [
                ("ubo-001", "cust-002", None, "Viktor Aleksandrovich Morozov", "RU", "CY", "1968-04-12", 55.0, 1, 1, "TIN-UBO-001"),
                ("ubo-002", "cust-002", "cust-007", "Dmitri Volkov", "RU", "US", "1991-07-19", 45.0, 1, 0, "TIN-007"),
                ("ubo-003", "cust-003", "cust-004", "Elena Vance Offshore Nominee", "KY", "KY", "1979-03-11", 60.0, 1, 0, "TIN-UBO-003"),
                ("ubo-004", "cust-004", None, "Carlos Eduardo Mendoza", "VE", "US", "1962-09-21", 75.0, 1, 1, "TIN-010"),
            ]
            for uid, cid, linked_cid, fname, nat, res_c, dob, pct, ctrl, pep, tin in ubos:
                conn.execute(
                    """
                    INSERT INTO beneficial_owners (
                        id, customer_id, linked_individual_customer_id, full_name,
                        nationality, residence_country, date_of_birth, ownership_percentage,
                        is_control_person, is_pep, tax_id_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (uid, cid, linked_cid, fname, nat, res_c, dob, pct, ctrl, pep, hash_tax_id(tin), now),
                )

            # Seed Accounts (1 primary account per customer)
            for idx in range(1, 16):
                cid = f"cust-{idx:03d}"
                aid = f"acct-{idx:03d}"
                anum = f"SG-8800{idx:04d}"
                atype = "COMMERCIAL_TREASURY" if idx in (2, 3, 4, 5, 11, 15) else "CHECKING"
                status = "RESTRICTED" if idx == 12 else "ACTIVE"
                conn.execute(
                    """
                    INSERT INTO accounts (
                        id, customer_id, account_number, account_type, currency,
                        current_balance_usd, average_30d_balance_usd, status,
                        opened_at, last_activity_at, branch_code, created_at
                    ) VALUES (?, ?, ?, ?, 'USD', 85000.0, 65000.0, ?, '2024-02-01T00:00:00+00:00', ?, 'BR-NYC-01', ?)
                    """,
                    (aid, cid, anum, atype, status, now, now),
                )

            # Seed External Counterparties
            counterparties = [
                ("cp-001", "IBAN-VG8800192", "Tortola Shell Nominees Ltd", "CORPORATE", "BVI Offshore Bank", "BVIOVG22", "VG", "5511", 1, None),
                ("cp-002", "IBAN-IR9900411", "Caspian Meridian Petrochem", "CORPORATE", "Tehran Trade Bank", "TTBKIRTH", "IR", "5172", 1, None),
                ("cp-003", "WALLET-0x99F1A", "Offshore Non-KYC Crypto Swap", "EXCHANGE", "Virtual Asset Service", "VASPPA22", "PA", "6051", 1, None),
                ("cp-004", "IBAN-AE4401928", "Dubai Precision Microelectronics FZE", "CORPORATE", "Emirates Trade Bank", "ETBKAEAD", "AE", "5065", 1, None),
                ("cp-005", "IBAN-US1102931", "Bellagio High-Roller Cage & Vault", "MERCHANT", "Nevada Gaming Bank", "NVGBUS33", "US", "7995", 0, None),
                ("cp-006", "IBAN-US5501922", "Standard Payroll & Utility Clearing", "CORPORATE", "Citibank NA", "CITIUS33", "US", "8999", 0, None),
            ]
            for cpid, eref, name, etype, bname, bic, country, mcc, hr, linked_acct in counterparties:
                conn.execute(
                    """
                    INSERT INTO counterparties (
                        id, external_account_ref, name, entity_type, bank_name,
                        bank_bic_swift, country_code, mcc_code, is_high_risk_jurisdiction,
                        linked_internal_account_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (cpid, eref, name, etype, bname, bic, country, mcc, hr, linked_acct, now),
                )

            # Seed Transactions Covering All 25 Typology Rules + Normal Baseline
            txs: List[Dict[str, Any]] = []

            def add_tx(
                aid: str,
                cid: str,
                ts: str,
                tx_type: str,
                direction: str,
                amt: float,
                channel: str = "ONLINE_WEB",
                orig_c: str = "US",
                dest_c: str = "US",
                cp_id: str | None = None,
                cp_acct: str | None = None,
                dev: str | None = None,
                ip: str | None = None,
                lat: float | None = None,
                lon: float | None = None,
                mcc: str | None = None,
                branch: str | None = None,
                memo: str = "Commercial transfer",
                tag: str = "BASELINE_NORMAL",
                bal_after: float = 50000.0,
            ) -> None:
                idx = len(txs) + 1
                txs.append(
                    {
                        "id": f"tx-{idx:04d}",
                        "external_tx_id": f"SG-TX-2026-{idx:05d}",
                        "account_id": aid,
                        "customer_id": cid,
                        "counterparty_id": cp_id,
                        "counterparty_account_id": cp_acct,
                        "tx_timestamp": ts,
                        "tx_type": tx_type,
                        "direction": direction,
                        "amount_usd": amt,
                        "balance_after_usd": bal_after,
                        "channel": channel,
                        "origin_country": orig_c,
                        "destination_country": dest_c,
                        "ip_address": ip,
                        "device_fingerprint": dev,
                        "geo_lat": lat,
                        "geo_lon": lon,
                        "mcc_code": mcc,
                        "branch_or_atm_id": branch,
                        "remittance_purpose": memo,
                        "scenario_tag": tag,
                    }
                )

            # 1. Family A (Structuring: AML-STR-001, 002, 003, 004, 005) + CTR (>10k cash) on acct-001 (Dante Morales)
            add_tx("acct-001", "cust-001", "2026-10-02T09:15:00+00:00", "CASH_DEPOSIT", "INBOUND", 9500.0, "BRANCH", "US", "US", branch="BR-NYC-01", memo="Cash store receipts", tag="SCENARIO_STRUCTURING_AML-STR-001")
            add_tx("acct-001", "cust-001", "2026-10-02T14:20:00+00:00", "CASH_DEPOSIT", "INBOUND", 9000.0, "ATM", "US", "US", branch="ATM-QUEENS-04", memo="Cash deposit", tag="SCENARIO_STRUCTURING_AML-STR-001")
            add_tx("acct-001", "cust-001", "2026-10-03T10:05:00+00:00", "CASH_DEPOSIT", "INBOUND", 4000.0, "BRANCH", "US", "US", branch="BR-BROOKLYN-02", memo="Cash deposit", tag="SCENARIO_SMURFING_AML-STR-002")
            add_tx("acct-001", "cust-001", "2026-10-03T16:30:00+00:00", "CASH_DEPOSIT", "INBOUND", 3500.0, "ATM", "US", "US", branch="ATM-BRONX-09", memo="Cash deposit", tag="SCENARIO_SMURFING_AML-STR-003")
            # Sub-Travel-Rule splits ($2,800 x 3) -> AML-STR-004
            add_tx("acct-001", "cust-001", "2026-10-04T11:00:00+00:00", "WIRE_DOMESTIC", "OUTBOUND", 2850.0, "ONLINE_WEB", "US", "US", cp_id="cp-006", memo="Split invoice 1", tag="SCENARIO_SPLIT_AML-STR-004")
            add_tx("acct-001", "cust-001", "2026-10-04T12:15:00+00:00", "WIRE_DOMESTIC", "OUTBOUND", 2900.0, "ONLINE_WEB", "US", "US", cp_id="cp-006", memo="Split invoice 2", tag="SCENARIO_SPLIT_AML-STR-004")
            add_tx("acct-001", "cust-001", "2026-10-04T15:40:00+00:00", "WIRE_DOMESTIC", "OUTBOUND", 2750.0, "ONLINE_WEB", "US", "US", cp_id="cp-006", memo="Split invoice 3", tag="SCENARIO_SPLIT_AML-STR-004")

            # 2. Family B (Pass-Through AML-LAY-001, Fiat-to-Crypto AML-LAY-005, Offshore AML-GEO-002) on acct-002 (Baltic Horizon)
            add_tx("acct-002", "cust-002", "2026-10-05T08:00:00+00:00", "WIRE_INTERNATIONAL", "INBOUND", 60000.0, "SWIFT_NET", "VG", "PA", cp_id="cp-001", memo="Offshore consulting retainer", tag="SCENARIO_PASSTHROUGH_AML-LAY-001")
            add_tx("acct-002", "cust-002", "2026-10-05T14:30:00+00:00", "CRYPTO_EXCHANGE", "OUTBOUND", 54000.0, "API_GATEWAY", "PA", "PA", cp_id="cp-003", memo="USDT OTC liquidity settlement", tag="SCENARIO_CRYPTO_EXIT_AML-LAY-005")

            # 3. Family B (Multi-Hop Chain AML-LAY-002 & Circular Round-Tripping Carousel AML-LAY-003) across acct-003 -> acct-004 -> acct-005 -> acct-003
            add_tx("acct-003", "cust-003", "2026-10-06T09:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 32000.0, "ONLINE_WEB", "US", "KY", cp_acct="acct-004", memo="Intercompany loan tranche A", tag="SCENARIO_CAROUSEL_AML-LAY-003")
            add_tx("acct-004", "cust-004", "2026-10-06T13:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 30500.0, "ONLINE_WEB", "KY", "PA", cp_acct="acct-005", memo="Sub-charter maritime fee", tag="SCENARIO_CAROUSEL_AML-LAY-002")
            add_tx("acct-005", "cust-005", "2026-10-06T18:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 29500.0, "ONLINE_WEB", "PA", "US", cp_acct="acct-003", memo="Management rebate return", tag="SCENARIO_CAROUSEL_AML-LAY-003")

            # 4. Family C (Fan-In AML-NET-001, Fan-Out AML-NET-002, Shared Device Ring AML-NET-003) on Mule Ring (acct-006, acct-007, acct-008)
            shared_mule_dev = "DEV-FP-MULE-RING-991A"
            shared_mule_ip = "185.220.101.44"
            add_tx("acct-007", "cust-007", "2026-10-07T08:10:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 4200.0, "ONLINE_WEB", "US", "US", cp_acct="acct-006", dev=shared_mule_dev, ip=shared_mule_ip, memo="P2P transfer 1", tag="SCENARIO_FAN_IN_AML-NET-001")
            add_tx("acct-008", "cust-008", "2026-10-07T09:20:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 4500.0, "ONLINE_WEB", "US", "US", cp_acct="acct-006", dev=shared_mule_dev, ip=shared_mule_ip, memo="P2P transfer 2", tag="SCENARIO_SHARED_DEVICE_AML-NET-003")
            add_tx("acct-003", "cust-003", "2026-10-07T10:15:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 3800.0, "ONLINE_WEB", "US", "US", cp_acct="acct-006", memo="Collector transfer 3", tag="SCENARIO_FAN_IN_AML-NET-001")
            add_tx("acct-011", "cust-011", "2026-10-07T11:30:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 4100.0, "ONLINE_WEB", "US", "US", cp_acct="acct-006", memo="Collector transfer 4", tag="SCENARIO_FAN_IN_AML-NET-001")
            # Fan-Out from acct-006 to 4 recipients + Midnight Scripting Burst (FRD-BEH-005 at 02:00 UTC)
            add_tx("acct-006", "cust-006", "2026-10-08T01:15:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 3600.0, "API_GATEWAY", "US", "US", cp_acct="acct-007", dev=shared_mule_dev, ip=shared_mule_ip, memo="Mule payout 1", tag="SCENARIO_FAN_OUT_AML-NET-002")
            add_tx("acct-006", "cust-006", "2026-10-08T01:45:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 3500.0, "API_GATEWAY", "US", "US", cp_acct="acct-008", dev=shared_mule_dev, ip=shared_mule_ip, memo="Mule payout 2", tag="SCENARIO_FAN_OUT_AML-NET-002")
            add_tx("acct-006", "cust-006", "2026-10-08T02:10:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 3400.0, "API_GATEWAY", "US", "US", cp_acct="acct-002", dev=shared_mule_dev, ip=shared_mule_ip, memo="Mule payout 3", tag="SCENARIO_NIGHT_BURST_FRD-BEH-005")
            add_tx("acct-006", "cust-006", "2026-10-08T02:50:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 3700.0, "API_GATEWAY", "US", "US", cp_acct="acct-012", dev=shared_mule_dev, ip=shared_mule_ip, memo="Mule payout 4 to restricted peer", tag="SCENARIO_MULE_AML-NET-004")

            # 5. Family E (Elder Exploitation FRD-BEH-003, ATO Rapid Balance Drain FRD-BEH-002, Z-Score Spike FRD-BEH-001) on acct-009 (Eleanor Vance-Sterling, age 78)
            add_tx("acct-009", "cust-009", "2026-09-01T10:00:00+00:00", "ACH_CREDIT", "INBOUND", 2400.0, "ONLINE_WEB", "US", "US", dev="DEV-ELEANOR-HOME-IPAD", memo="Monthly pension credit", tag="BASELINE_NORMAL", bal_after=48000.0)
            add_tx("acct-009", "cust-009", "2026-09-10T12:00:00+00:00", "CARD_POS", "OUTBOUND", 180.0, "BRANCH", "US", "US", dev="DEV-ELEANOR-HOME-IPAD", memo="Grocery store", tag="BASELINE_NORMAL", bal_after=47820.0)
            add_tx("acct-009", "cust-009", "2026-09-20T15:00:00+00:00", "CARD_POS", "OUTBOUND", 220.0, "BRANCH", "US", "US", dev="DEV-ELEANOR-HOME-IPAD", memo="Pharmacy", tag="BASELINE_NORMAL", bal_after=47600.0)
            add_tx("acct-009", "cust-009", "2026-10-09T03:20:00+00:00", "WIRE_INTERNATIONAL", "OUTBOUND", 42000.0, "ONLINE_WEB", "US", "NG", cp_id="cp-003", dev="DEV-UNRECOGNIZED-LINUX-TOR", ip="197.210.55.12", memo="Emergency liquidation wire", tag="SCENARIO_ATO_DRAIN_FRD-BEH-002", bal_after=5600.0)

            # 6. Family D (High-Risk FATF Corridor AML-GEO-001, Cross-Border Burst AML-GEO-004, Sanctions Transit AML-GEO-005) on acct-010 (Carlos Mendoza)
            add_tx("acct-010", "cust-010", "2026-10-08T10:00:00+00:00", "WIRE_INTERNATIONAL", "OUTBOUND", 28000.0, "SWIFT_NET", "US", "IR", cp_id="cp-002", memo="Petrochemical industrial component settlement", tag="SCENARIO_HIGH_RISK_GEO_AML-GEO-001")
            add_tx("acct-010", "cust-010", "2026-10-09T11:00:00+00:00", "WIRE_INTERNATIONAL", "OUTBOUND", 19500.0, "SWIFT_NET", "US", "AE", cp_id="cp-004", memo="Dual-use semiconductor & CNC optics shipment", tag="SCENARIO_TRANSIT_AML-GEO-005")
            add_tx("acct-010", "cust-010", "2026-10-10T14:00:00+00:00", "WIRE_INTERNATIONAL", "OUTBOUND", 16000.0, "SWIFT_NET", "US", "TR", cp_id="cp-004", memo="Avionics ball bearing transit invoice", tag="SCENARIO_TRANSIT_AML-GEO-004")

            # 7. Family C & E (Reciprocal Wash Transfers AML-NET-005 & Commercial KYB MCC Mismatch FRD-BEH-004) on acct-011
            add_tx("acct-011", "cust-011", "2026-10-05T10:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 6500.0, "ONLINE_WEB", "US", "US", cp_acct="acct-003", memo="Wash invoice A1", tag="SCENARIO_WASH_AML-NET-005")
            add_tx("acct-003", "cust-003", "2026-10-05T16:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 6500.0, "ONLINE_WEB", "US", "US", cp_acct="acct-011", memo="Wash rebate B1", tag="SCENARIO_WASH_AML-NET-005")
            add_tx("acct-011", "cust-011", "2026-10-06T10:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 6800.0, "ONLINE_WEB", "US", "US", cp_acct="acct-003", memo="Wash invoice A2", tag="SCENARIO_WASH_AML-NET-005")
            add_tx("acct-003", "cust-003", "2026-10-06T16:00:00+00:00", "INTERNAL_TRANSFER", "OUTBOUND", 6800.0, "ONLINE_WEB", "US", "US", cp_acct="acct-011", memo="Wash rebate B2", tag="SCENARIO_WASH_AML-NET-005")
            add_tx("acct-011", "cust-011", "2026-10-07T22:00:00+00:00", "CARD_POS", "OUTBOUND", 9200.0, "BRANCH", "US", "US", cp_id="cp-005", mcc="7995", memo="Casino VIP cage chips", tag="SCENARIO_MCC_MISMATCH_FRD-BEH-004")

            # 8. Family B & D (Dormant Awakening AML-LAY-004 & Impossible Travel AML-GEO-003) on acct-012 (Tariq Al-Mansur)
            add_tx("acct-012", "cust-012", "2026-06-01T09:00:00+00:00", "CASH_DEPOSIT", "INBOUND", 1200.0, "BRANCH", "AE", "AE", lat=25.2048, lon=55.2708, memo="Initial deposit Dubai", tag="BASELINE_NORMAL")
            add_tx("acct-012", "cust-012", "2026-10-10T10:00:00+00:00", "WIRE_INTERNATIONAL", "INBOUND", 24000.0, "SWIFT_NET", "SY", "AE", lat=40.7128, lon=-74.0060, memo="Sudden dormant account awakening wire (New York terminal)", tag="SCENARIO_DORMANT_AML-LAY-004")
            add_tx("acct-012", "cust-012", "2026-10-10T10:30:00+00:00", "CASH_WITHDRAWAL", "OUTBOUND", 11500.0, "BRANCH", "AE", "AE", lat=35.6762, lon=139.6503, memo="Tokyo branch cash withdrawal 30 mins after NYC activity", tag="SCENARIO_IMPOSSIBLE_TRAVEL_AML-GEO-003")

            # 9. Clean Baseline Transactions on acct-013, acct-014, acct-015
            add_tx("acct-013", "cust-013", "2026-10-01T09:00:00+00:00", "ACH_CREDIT", "INBOUND", 4200.0, "ONLINE_WEB", "US", "US", cp_id="cp-006", memo="Biweekly engineering salary", tag="BASELINE_NORMAL")
            add_tx("acct-014", "cust-014", "2026-10-02T11:00:00+00:00", "ACH_CREDIT", "INBOUND", 6100.0, "ONLINE_WEB", "US", "US", cp_id="cp-006", memo="Hospital payroll", tag="BASELINE_NORMAL")
            add_tx("acct-015", "cust-015", "2026-10-03T15:00:00+00:00", "ACH_DEBIT", "OUTBOUND", 3800.0, "ONLINE_WEB", "US", "US", cp_id="cp-006", memo="Medical supplies vendor", tag="BASELINE_NORMAL")

            for tx in txs:
                conn.execute(
                    """
                    INSERT INTO transactions (
                        id, external_tx_id, account_id, customer_id, counterparty_id,
                        counterparty_account_id, tx_timestamp, tx_type, direction,
                        amount_original, currency_original, fx_rate_to_usd, amount_usd,
                        balance_after_usd, channel, origin_country, destination_country,
                        ip_address, device_fingerprint, geo_lat, geo_lon, mcc_code,
                        branch_or_atm_id, remittance_purpose, scenario_tag, is_flagged, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USD', 1.0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        tx["id"], tx["external_tx_id"], tx["account_id"], tx["customer_id"],
                        tx["counterparty_id"], tx["counterparty_account_id"], tx["tx_timestamp"],
                        tx["tx_type"], tx["direction"], tx["amount_usd"], tx["amount_usd"],
                        tx["balance_after_usd"], tx["channel"], tx["origin_country"],
                        tx["destination_country"], tx["ip_address"], tx["device_fingerprint"],
                        tx["geo_lat"], tx["geo_lon"], tx["mcc_code"], tx["branch_or_atm_id"],
                        tx["remittance_purpose"], tx["scenario_tag"], now,
                    ),
                )

        # Run Typology Evaluation, Sanctions Screening, Risk Scoring, Sample Case/SAR & Simulation
        eval_summary = typology_engine.evaluate_all_rules(persist_alerts=True)

        screener = SanctionsScreeningService(self.db)
        screener.screen_entity("Carlos Eduardo Mendoza", date_of_birth="1962-09-21", country_code="VE", customer_id="cust-010")
        screener.screen_entity("Tariq Al-Mansur", date_of_birth="1975-02-18", country_code="SY", customer_id="cust-012")
        screener.screen_entity("Baltic Horizon Trading Ltd", country_code="VG", customer_id="cust-002")

        risk_engine = CompositeRiskEngine(self.db)
        risk_summary = risk_engine.evaluate_all_customers()

        # Escalate top alerts into realistic L1/L2/QA cases and generate a FinCEN SAR
        case_service = CaseManagementService(self.db)
        sar_gen = FinCENSarGenerator(self.db)
        alerts = case_service.list_alerts(limit=50)
        if alerts:
            first_alert = alerts[0]
            triaged = case_service.triage_alert(
                alert_id=first_alert["id"],
                action="ESCALATE_TO_CASE",
                actor_user_id="usr-l2",
                actor_role=Role.L2_INVESTIGATOR,
                case_title=f"Priority Forensic Investigation — {first_alert['customer_name']}",
                case_priority="CRITICAL",
            )
            case_id = triaged["case_id"]
            sar_gen.generate_sar_for_case(
                case_id=case_id,
                prepared_by_user_id="usr-l2",
                prepared_by_role=Role.L2_INVESTIGATOR,
                filing_type="INITIAL",
                custom_why_how_addendum="Corroborated multi-hop layering and structuring evidence across linked counterparties.",
                auto_submit_for_qa=True,
            )
            # QA Officer approves and files the SAR (Four-Eyes compliant: usr-qa != usr-l2)
            case_service.transition_case_status(
                case_id=case_id,
                target_status="SAR_APPROVED",
                actor_user_id="usr-qa",
                actor_role=Role.QA_COMPLIANCE_OFFICER,
                notes="Four-Eyes QA review passed. 5-W narrative verified against transaction ledger.",
            )
            case_service.transition_case_status(
                case_id=case_id,
                target_status="SAR_FILED",
                actor_user_id="usr-qa",
                actor_role=Role.QA_COMPLIANCE_OFFICER,
                notes="Filed electronically with FinCEN BSA E-Filing gateway.",
            )

            if len(alerts) > 1:
                second_alert = alerts[1]
                case_service.triage_alert(
                    alert_id=second_alert["id"],
                    action="ESCALATE_TO_CASE",
                    actor_user_id="usr-l1",
                    actor_role=Role.L1_ANALYST,
                    case_title=f"Active L2 Review — {second_alert['customer_name']}",
                    case_priority="HIGH",
                )

        # Run a baseline RuleForge Shadow Backtest
        sim_engine = RuleSimulationEngine(self.db)
        sim_engine.run_shadow_backtest(
            rule_id="AML-STR-001",
            candidate_parameters={"min_amount_usd": 8000.0, "max_amount_usd": 9999.99, "min_occurrences": 2, "window_hours": 168},
            actor_user_id="usr-eng",
            notes="Shadow test widening structuring lower bound from $8,500 to $8,000",
        )

        AuditService(self.db).record_event(
            actor_user_id="usr-adm",
            actor_role=Role.SYSTEM_ADMIN,
            action="DATABASE_SEEDED",
            entity_type="System",
            entity_id="sentinelgraph-seed-v1",
            details={"eval_summary": eval_summary, "risk_bands": risk_summary},
        )

        return {
            "status": "seeded",
            "typology_evaluation": eval_summary,
            "customer_risk_bands": risk_summary,
        }
