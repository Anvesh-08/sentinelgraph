# Windows PowerShell Environment Setup Script for SentinelGraph
# Usage in VS Code PowerShell Terminal: .\scripts\setup_windows.ps1

$ErrorActionPreference = "Stop"
Write-Host "=== SentinelGraph: Windows PowerShell Environment Setup ===" -ForegroundColor Cyan

if (-not (Test-Path ".venv")) {
    Write-Host "[1/4] Creating Python virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "[2/4] Activating virtual environment and installing dependencies..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\pip.exe install -r requirements.txt

if (-not (Test-Path ".env")) {
    Write-Host "[3/4] Copying .env.example to .env..." -ForegroundColor Yellow
    Copy-Item .env.example .env
}

Write-Host "[4/4] Applying SQL migrations and seeding synthetic AML/Fraud scenarios..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m backend.app.cli.main init-db --seed

Write-Host "Setup complete! Run '.\scripts\run_checks.ps1' to execute tests or launch the server." -ForegroundColor Green
