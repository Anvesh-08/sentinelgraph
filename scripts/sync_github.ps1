# Windows PowerShell Git Identity & GitHub Sync Script
# Run inside VS Code PowerShell Terminal: .\scripts\sync_github.ps1

$ErrorActionPreference = "Stop"
Write-Host "=== SentinelGraph v2.0 (31,000+ LOC / 50 Commits): GitHub Sync Helper ===" -ForegroundColor Cyan

$gitName = git config user.name
$gitEmail = git config user.email

if (-not $gitName -or $gitName -eq "SentinelGraph Architect") {
    $gitName = Read-Host "Enter your full name for Git commits"
    git config user.name "$gitName"
}
if (-not $gitEmail -or $gitEmail -eq "architect@sentinelgraph.local") {
    $gitEmail = Read-Host "Enter your GitHub email address"
    git config user.email "$gitEmail"
}

Write-Host "[1/3] Stamping all 50 commits with author: $gitName <$gitEmail>..." -ForegroundColor Yellow
$env:FILTER_BRANCH_SQUELCH_WARNING=1
git filter-branch -f --env-filter "GIT_AUTHOR_NAME='$gitName'; GIT_AUTHOR_EMAIL='$gitEmail'; GIT_COMMITTER_NAME='$gitName'; GIT_COMMITTER_EMAIL='$gitEmail';" -- --all

Write-Host "[2/3] Running full 174-test verification suite and Project Sirius readiness audit..." -ForegroundColor Yellow
python -m unittest discover -s tests -p "test_*.py"
python scripts/verify_sirius_readiness.py

Write-Host "[3/3] Ready to push! If your GitHub remote 'origin' is configured, run:" -ForegroundColor Green
Write-Host "  git push -u origin main --force" -ForegroundColor Cyan
Write-Host "  git push origin --all --force" -ForegroundColor Cyan
