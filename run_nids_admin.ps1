# NIDS Real Packet Capture Setup Script
# Run this script as Administrator for real packet capture

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "    NIDS - Real Packet Capture Mode" -ForegroundColor Cyan  
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "❌ This script requires Administrator privileges for packet capture!" -ForegroundColor Red
    Write-Host "💡 Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Running with Administrator privileges" -ForegroundColor Green
Write-Host ""

# Check for packet capture libraries
Write-Host "🔍 Checking packet capture requirements..." -ForegroundColor Yellow

# Check if Npcap/WinPcap is installed
$npcapPath = "C:\Windows\System32\Npcap"
$winpcapPath = "C:\Windows\System32\wpcap.dll"

if (Test-Path $npcapPath) {
    Write-Host "✅ Npcap found" -ForegroundColor Green
}
elseif (Test-Path $winpcapPath) {
    Write-Host "✅ WinPcap found" -ForegroundColor Green
}
else {
    Write-Host "⚠️  Npcap/WinPcap not found - packet capture may not work" -ForegroundColor Yellow
    Write-Host "💡 Install Npcap from: https://nmap.org/npcap/" -ForegroundColor Cyan
}

Write-Host ""

# Activate virtual environment
Write-Host "🔧 Activating virtual environment..." -ForegroundColor Yellow
Set-Location "backend"
& ".\venv_clean\Scripts\Activate.ps1"

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to activate virtual environment" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Virtual environment activated" -ForegroundColor Green
Write-Host ""

# Start NIDS backend
Write-Host "🚀 Starting NIDS backend with real packet capture..." -ForegroundColor Green
Write-Host "📊 Dashboard will be available at: http://localhost:8000" -ForegroundColor Cyan
Write-Host "📖 API Documentation at: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

try {
    python main_working.py
}
catch {
    Write-Host "❌ Error starting NIDS backend: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Write-Host ""
    Write-Host "NIDS backend stopped." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
}
