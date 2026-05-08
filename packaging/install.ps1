# =============================================================================
# AgentGuard — Bootstrap installer (Windows PowerShell)
# =============================================================================
#
# Uso recomendado:
#   irm https://get.agentguard.io | iex
#
# Qué hace:
#   1. Detecta arquitectura (x64 / arm64)
#   2. Descarga los binarios desde GitHub Releases
#   3. Verifica checksum SHA-256
#   4. Instala en C:\Program Files\AgentGuard
#   5. Crea config inicial con `agentguard init --defaults`
#   6. Registra e inicia Windows Service (requiere Admin)
#
# Requisitos:
#   - PowerShell 5.1+ o PowerShell Core 7+
#   - Ejecutar como Administrador para protección completa
# =============================================================================

param(
    [string]$Version = $env:AGENTGUARD_VERSION ?? "latest"
)

$ErrorActionPreference = "Stop"

# ── Configuración ────────────────────────────────────────────
$Repo = "tuorg/agentguard"
$BaseUrl = "https://github.com/$Repo/releases"
$InstallDir = "${env:ProgramFiles}\AgentGuard"
$ConfigDir = "${env:ProgramData}\AgentGuard"

# ── Helpers ──────────────────────────────────────────────────
function Write-Info  { Write-Host "  → $args" }
function Write-Success { Write-Host "  ✓ $args" -ForegroundColor Green }
function Write-Warn   { Write-Host "  ! $args" -ForegroundColor Yellow }
function Write-Die    { Write-Host "  ✗ $args" -ForegroundColor Red; exit 1 }

# ── Detección ────────────────────────────────────────────────
function Get-Arch {
    $arch = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default { Write-Die "Unsupported architecture: $arch" }
    }
}

function Get-Target {
    $arch = Get-Arch
    return "${arch}-pc-windows-msvc"
}

# ── Download ─────────────────────────────────────────────────
function Download-File {
    param([string]$Url, [string]$Dest)
    Write-Info "Downloading $(Split-Path $Dest -Leaf)..."
    Invoke-WebRequest -Uri $Url -OutFile $Dest -MaximumRetryCount 3 -TimeoutSec 120
}

function Test-Sha256 {
    param([string]$File, [string]$Expected)
    $actual = (Get-FileHash -Algorithm SHA256 $File).Hash.ToLower()
    if ($actual -ne $Expected.ToLower()) {
        Write-Die "Checksum mismatch for $(Split-Path $File -Leaf)`n  Expected: $Expected`n  Got:      $actual"
    }
    Write-Success "Checksum verified"
}

# ── Instalación ──────────────────────────────────────────────
function Install-Windows {
    $target = Get-Target
    Write-Info "Installing AgentGuard for Windows ($target)..."

    $tmp = Join-Path $env:TEMP "agentguard-install"
    New-Item -ItemType Directory -Force $tmp | Out-Null

    $cliUrl = "$BaseUrl/$Version/agentguard-cli-${target}.exe"
    $daemonUrl = "$BaseUrl/$Version/agentguard-windows-${target}.exe"
    $checksumUrl = "$BaseUrl/$Version/checksums.txt"

    $cliBin = Join-Path $tmp "agentguard.exe"
    $daemonBin = Join-Path $tmp "agentguard-windows.exe"
    $checksums = Join-Path $tmp "checksums.txt"

    Download-File $cliUrl $cliBin
    Download-File $daemonUrl $daemonBin
    try { Download-File $checksumUrl $checksums } catch { Write-Warn "No checksums file found" }

    if (Test-Path $checksums) {
        $checksumContent = Get-Content $checksums
        $cliExpected = ($checksumContent | Select-String "agentguard-cli-${target}" | ForEach-Object { ($_ -split '\s+')[1] })
        $daemonExpected = ($checksumContent | Select-String "agentguard-windows-${target}" | ForEach-Object { ($_ -split '\s+')[1] })
        if ($cliExpected) { Test-Sha256 $cliBin $cliExpected }
        if ($daemonExpected) { Test-Sha256 $daemonBin $daemonExpected }
    }

    # Instalar binarios
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    Copy-Item $cliBin (Join-Path $InstallDir "agentguard.exe") -Force
    Copy-Item $daemonBin (Join-Path $InstallDir "agentguard-windows.exe") -Force
    Write-Success "Binaries installed to $InstallDir"

    # Añadir al PATH
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($currentPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$InstallDir", "Machine")
        Write-Info "Added $InstallDir to system PATH (restart terminal to apply)"
    }

    # Generar config por defecto
    New-Item -ItemType Directory -Force $ConfigDir | Out-Null
    $configFile = Join-Path $ConfigDir "config.toml"
    if (-not (Test-Path $configFile)) {
        Write-Info "Generating default config..."
        @'
# AgentGuard — default configuration (Windows)
[agentguard]
version = "1"

protected_dirs = []
protected_files = []

[[agent_processes]]
name = "claude"

[[agent_processes]]
name = "cursor"

[on_violation]
snapshot_on_violation = true
kill_process = false

[dlp]
enabled = true
proxy_port = 7771
action = "block"

[vault]
snapshot_on_start = true
keep_days = 30
'@ | Out-File -FilePath $configFile -Encoding UTF8
        Write-Success "Config written to $configFile"
    }

    # Registrar Windows Service
    $serviceName = "AgentGuard"
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $existingService) {
        Write-Info "Registering Windows Service..."
        $binPath = Join-Path $InstallDir "agentguard-windows.exe"
        Start-Process sc.exe -ArgumentList @(
            "create", $serviceName,
            "binPath=", "`"$binPath --service`"",
            "start=", "auto",
            "type=", "own",
            "obj=", "LocalSystem"
        ) -Wait -NoNewWindow
        Write-Info "Starting service..."
        Start-Service $serviceName -ErrorAction SilentlyContinue
        Write-Success "Windows Service registered and started"
    } else {
        Write-Info "Service already exists — restarting..."
        Restart-Service $serviceName -ErrorAction SilentlyContinue
    }

    # Añadir CA al trust store
    # NOTE: filename must match `CA_CERT_FILE` in agentguard-core/src/ca.rs
    $caCert = Join-Path $ConfigDir "ca\root.crt"
    if (Test-Path $caCert) {
        Write-Info "Adding AgentGuard CA to system trust store..."
        certutil -addstore -f "ROOT" $caCert 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "CA root added to trust store"
        } else {
            Write-Warn "Could not add CA to trust store. Add manually:"
            Write-Warn "  certutil -addstore ROOT $caCert"
        }
    }

    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

    Write-Success "AgentGuard installed for Windows!"
    Write-Host ""
    Write-Info "Next steps:"
    Write-Host "  1. Edit config:   notepad ${configFile}"
    Write-Host "  2. Check status:   agentguard status"
    Write-Host "  3. Protect a dir:  agentguard protect ${env:USERPROFILE}\Documents"
    Write-Host ""
}

# ── Entry point ──────────────────────────────────────────────
Write-Host "AgentGuard Installer" -ForegroundColor Cyan
Write-Host ""

$target = Get-Target
Write-Info "Detected: Windows ($target)"

# Comprobar elevación
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Warn "Running without Administrator privileges."
    Write-Warn "For full protection (NTFS DENY ACEs + Windows Service), restart as Administrator."
    Write-Warn "Continuing with user-mode-only installation..."
}

Write-Host ""
$confirm = Read-Host "Install AgentGuard for Windows? [Y/n]"
if ($confirm -and $confirm -notmatch '^[Yy]') {
    Write-Die "Installation cancelled"
}

Install-Windows
