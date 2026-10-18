"""
Command-Line Interface (`python -m backend.app.cli.main`) for SentinelGraph.
Supports:
- `init-db [--seed]`: Applies migrations and seeds synthetic financial crime topologies.
- `evaluate-rules`: Runs all 25 AML/fraud typology rules against the transaction ledger.
- `verify-audit`: Verifies the HMAC-SHA256 hash chain across `audit_logs`.
- `audit-security`: Scans the repository for hardcoded secrets, private keys, or `.env` leaks.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

from backend.app.audit.service import AuditService
from backend.app.db.connection import default_db
from backend.app.db.migrator import MigrationRunner
from backend.app.ingestion.seeder import SyntheticCrimeSeeder
from backend.app.typologies.engine import TypologyEngine


FORBIDDEN_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub Personal Access Token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
]


def run_security_hygiene_scan(repo_root: Path) -> Dict[str, Any]:
    findings: List[Dict[str, str]] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if any(part in rel for part in (".git/", "__pycache__", ".venv/", "node_modules/", ".db")):
            continue
        if path.name == ".env":
            findings.append({"file": rel, "issue": "Committed .env file detected"})
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for label, pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern.search(text):
                findings.append({"file": rel, "issue": f"Potential {label} pattern matched"})
    return {
        "passed": len(findings) == 0,
        "findings": findings,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser( prog="sentinelgraph-cli", description="SentinelGraph Administrative CLI" )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-db", help="Run SQL migrations and optionally seed synthetic crime scenarios")
    p_init.add_argument("--seed", action="store_true", help="Seed synthetic customers, transactions, and typology scenarios")

    sub.add_parser("evaluate-rules", help="Run all 25 AML/Fraud typology rules on the current ledger")
    sub.add_parser("verify-audit", help="Verify cryptographic HMAC-SHA256 audit chain integrity")
    sub.add_parser("audit-security", help="Scan repository tree for forbidden secrets or .env leaks")

    args = parser.parse_args(argv)

    if args.command == "init-db":
        applied = MigrationRunner(default_db).run_migrations()
        result: Dict[str, Any] = {"migrations_applied": len(applied)}
        if args.seed:
            result["seed_result"] = SyntheticCrimeSeeder(default_db).seed_all()
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "evaluate-rules":
        res = TypologyEngine(default_db).evaluate_all_rules(persist_alerts=True)
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "verify-audit":
        res = AuditService(default_db).verify_chain_integrity(raise_on_error=False)
        print(json.dumps(res, indent=2))
        return 0 if res["is_valid"] else 1

    if args.command == "audit-security":
        repo_root = Path(__file__).resolve().parents[3]
        scan = run_security_hygiene_scan(repo_root)
        print(json.dumps(scan, indent=2))
        return 0 if scan["passed"] else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
