# Windows PowerShell Verification & Test Runner for SentinelGraph
# Usage: .\scripts\run_checks.ps1

$ErrorActionPreference = "Stop"
Write-Host "=== SentinelGraph: Running Automated Security, Audit & Test Suites ===" -ForegroundColor Cyan

Write-Host "[1/3] Running Repository Secret & Ownership Hygiene Check..." -ForegroundColor Yellow
python -m backend.app.cli.main audit-security

Write-Host "[2/3] Running Unit, Integration, and End-to-End Test Suites..." -ForegroundColor Yellow
python -m unittest discover -s tests -p "test_*.py" -v

Write-Host "[3/3] Running Project Sirius Repository Eligibility Audit..." -ForegroundColor Yellow
python scripts/verify_sirius_readiness.py
