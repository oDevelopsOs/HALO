# =============================================================================
# AgentGuard — Uninstaller (Windows PowerShell)
# =============================================================================

$ErrorActionPreference = "Continue"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

Write-Host "AgentGuard Uninstaller" -ForegroundColor Cyan
Write-Host ""

$confirm = Read-Host "Uninstall AgentGuard? [y/N]"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "Cancelled."
    exit 0
}
Write-Host ""

# Stop and remove service
Write-Host "  → Stopping and removing Windows Service..."
Stop-Service AgentGuard -Force -ErrorAction SilentlyContinue
Start-Process sc.exe -ArgumentList "delete","AgentGuard" -Wait -NoNewWindow -ErrorAction SilentlyContinue
Write-Host "  ✓ Service removed" -ForegroundColor Green

# Remove binaries
Write-Host "  → Removing binaries..."
$installDir = "${env:ProgramFiles}\AgentGuard"
if (Test-Path $installDir) {
    Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
}
Write-Host "  ✓ Binaries removed" -ForegroundColor Green

# Remove from PATH
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -like "*$installDir*") {
    $newPath = $currentPath -replace [Regex]::Escape(";$installDir"), "" -replace [Regex]::Escape("$installDir;"), ""
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
    Write-Host "  ✓ Removed from system PATH" -ForegroundColor Green
}

# Remove CA from trust store
Write-Host "  → Removing CA from trust store..."
certutil -delstore ROOT "AgentGuard DLP Local Root CA" 2>$null
Write-Host "  ✓ CA removed" -ForegroundColor Green

# Remove data
$removeData = Read-Host "  Remove C:\ProgramData\AgentGuard\? [y/N]"
if ($removeData -match '^[Yy]') {
    $dataDir = "${env:ProgramData}\AgentGuard"
    if (Test-Path $dataDir) {
        Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue
    }
    Write-Host "  ✓ Data removed" -ForegroundColor Green
} else {
    Write-Host "  → Data preserved"
}

Write-Host ""
Write-Host "  ✓ AgentGuard uninstalled" -ForegroundColor Green
