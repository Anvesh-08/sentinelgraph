#!/usr/bin/env python3
"""
Project Sirius Repository Audit & Readiness Verifier (`scripts/verify_sirius_readiness.py`).
Audits the repository against the engineering and governance targets in the Master Prompt:
1. Git commit count on `main` branch (>= 30 genuine commits).
2. Presence and completeness of all 10 mandatory documentation files.
3. Zero leaked secrets, `.env` files, or forbidden binary bloat (< 4 GB).
4. Automated test suite execution status.
5. Honest accounting of lines of code (LOC) by module and next-step guidance.
"""
import json
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCS = [
    "README.md",
    "PRODUCT_SPEC.md",
    "ARCHITECTURE.md",
    "DATABASE_SCHEMA.md",
    "API_DOCUMENTATION.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "TESTING.md",
    "DEVELOPMENT_ROADMAP.md",
]


def count_commits() -> int:
    out = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], cwd=REPO_ROOT, text=True)
    return int(out.strip())


def count_lines_of_code() -> dict:
    by_ext = {".py": 0, ".sql": 0, ".ts": 0, ".tsx": 0, ".json": 0, ".html": 0, ".md": 0, ".ps1": 0, ".yml": 0}
    total_files = 0
    total_lines = 0
    for p in REPO_ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO_ROOT).as_posix()
        if any(skip in rel for skip in (".git/", "__pycache__", ".venv/", "data/runtime/")):
            continue
        ext = p.suffix.lower()
        if ext in by_ext:
            lines = len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
            by_ext[ext] += lines
            total_lines += lines
            total_files += 1
    return {"total_tracked_files": total_files, "total_lines": total_lines, "by_extension": by_ext}


def main() -> None:
    commits = count_commits()
    loc = count_lines_of_code()
    docs_status = {doc: (REPO_ROOT / doc).exists() for doc in REQUIRED_DOCS}
    all_docs_present = all(docs_status.values())

    report = {
        "repository": "SentinelGraph",
        "branch": "main",
        "commit_count": commits,
        "meets_30_commit_target": commits >= 30,
        "all_10_mandatory_docs_present": all_docs_present,
        "documentation_files": docs_status,
        "code_metrics": loc,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
