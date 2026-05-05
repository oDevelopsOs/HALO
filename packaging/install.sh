#!/usr/bin/env bash
# =============================================================================
# AgentGuard — Bootstrap installer (Linux)
# =============================================================================
#
# Uso recomendado:
#   curl -fsSL https://get.agentguard.io | bash
#
# Qué hace:
#   1. Detecta SO (Linux) y arquitectura (x86_64 / aarch64)
#   2. Descarga los binarios correctos desde GitHub Releases
#   3. Verifica checksum SHA-256
#   4. Instala en /usr/local/bin
#   5. Genera config, crea directorios, instala systemd unit
#
# Requisitos:
#   - curl
#   - bash ≥ 3.2
#   - sha256sum (o shasum -a 256)
#   - sudo (para instalación de sistema, opcional)
# =============================================================================

set -euo pipefail

# ── Configuración ────────────────────────────────────────────
readonly REPO="tuorg/agentguard"
readonly VERSION="${AGENTGUARD_VERSION:-latest}"
readonly INSTALL_PREFIX="${AGENTGUARD_PREFIX:-/usr/local/bin}"
readonly BASE_URL="https://github.com/${REPO}/releases"

# Colores ANSI (opcional, si el terminal las soporta)
if [[ -t 1 ]]; then
    readonly BOLD='\033[1m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[0;33m'
    readonly RED='\033[0;31m'
    readonly NC='\033[0m'
else
    readonly BOLD='' GREEN='' YELLOW='' RED='' NC=''
fi

# ── Helpers ──────────────────────────────────────────────────
info()    { printf "${BOLD}  →${NC} %s\n" "$*"; }
success() { printf "${GREEN}${BOLD}  ✓${NC} %s\n" "$*"; }
warn()    { printf "${YELLOW}${BOLD}  !${NC} %s\n" "$*" >&2; }
die()     { printf "${RED}${BOLD}  ✗${NC} %s\n" "$*" >&2; exit 1; }

# ── Detección de SO ──────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux)  echo "linux" ;;
        Darwin) echo "macos" ;;
        *)      die "Unsupported OS: $(uname -s). AgentGuard currently runs on Linux." ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac
}

detect_target() {
    local os arch
    os="$(detect_os)"
    arch="$(detect_arch)"
    echo "${arch}-unknown-${os}-gnu"
}

# ── Download ─────────────────────────────────────────────────
download() {
    local url="$1" dest="$2"
    info "Downloading $(basename "$dest")..."
    curl -fsSL --max-time 120 --retry 3 -o "$dest" "$url" || die "Download failed: $url"
}

sha256_check() {
    local file="$1" expected="$2"
    local actual
    if command -v sha256sum &>/dev/null; then
        actual="$(sha256sum "$file" | cut -d' ' -f1)"
    elif command -v shasum &>/dev/null; then
        actual="$(shasum -a 256 "$file" | cut -d' ' -f1)"
    else
        warn "No sha256sum or shasum found — skipping checksum verification"
        return 0
    fi
    if [[ "$actual" != "$expected" ]]; then
        die "Checksum mismatch for $(basename "$file")\n  Expected: $expected\n  Got:      $actual"
    fi
    success "Checksum verified"
}

# ── Instalación de binarios ──────────────────────────────────
install_binary() {
    local src="$1" name="$2"
    local dest="${INSTALL_PREFIX}/${name}"
    sudo mkdir -p "$INSTALL_PREFIX" 2>/dev/null || mkdir -p "$INSTALL_PREFIX"
    if [[ -w "$INSTALL_PREFIX" ]]; then
        cp "$src" "$dest"
    else
        sudo cp "$src" "$dest"
    fi
    sudo chmod 755 "$dest" 2>/dev/null || chmod 755 "$dest"
    success "Installed $dest"
}

# ── Instalación Linux (systemd) ──────────────────────────────
install_linux() {
    local target="$1" tmp="$2"

    info "Installing AgentGuard for Linux ($target)..."

    # Descargar binarios
    local cli_url="${BASE_URL}/${VERSION}/agentguard-cli-${target}"
    local daemon_url="${BASE_URL}/${VERSION}/agentguard-linux-${target}"
    local checksum_url="${BASE_URL}/${VERSION}/checksums.txt"

    local cli_bin="${tmp}/agentguard"
    local daemon_bin="${tmp}/agentguard-linux"
    local checksums="${tmp}/checksums.txt"

    download "$cli_url" "$cli_bin"
    download "$daemon_url" "$daemon_bin"
    download "$checksum_url" "$checksums" || true

    if [[ -f "$checksums" ]]; then
        sha256_check "$cli_bin" "$(grep "agentguard-cli-${target}" "$checksums" | cut -d' ' -f1)"
        sha256_check "$daemon_bin" "$(grep "agentguard-linux-${target}" "$checksums" | cut -d' ' -f1)"
    fi

    install_binary "$cli_bin" "agentguard"
    install_binary "$daemon_bin" "agentguard-linux"

    # Generar config por defecto si no existe
    local config_dir="/etc/agentguard"
    local config_file="${config_dir}/config.toml"
    if [[ ! -f "$config_file" ]]; then
        info "Generating default config..."
        sudo mkdir -p "$config_dir" 2>/dev/null || mkdir -p "$config_dir"
        cat > "$tmp/config.toml" <<'CONFEOF'
# AgentGuard — default configuration
# See: https://agentguard.io/docs/config

[agentguard]
version = "1"

# Directories protected against deletion/renaming
protected_dirs = [
    # "/home/user/Documents",
    # "/home/user/Projects",
]

# Individual files protected against writes
protected_files = [
    # ".env",
    # "credentials.json",
]

# AI agent process identification
# [[agent_processes]]
# name = "claude"
# [[agent_processes]]
# name = "cursor"

[on_violation]
snapshot_on_violation = true
kill_process = false

[alerts]
desktop_notifications = true
sound = false

[vault]
snapshot_on_start = true
auto_snapshot_interval_hours = 6
keep_days = 30

[dlp]
enabled = true
proxy_port = 7771
action = "block"
CONFEOF
        if [[ -w "$config_dir" ]]; then
            cp "$tmp/config.toml" "$config_file"
        else
            sudo cp "$tmp/config.toml" "$config_file"
        fi
        success "Config written to $config_file"
    else
        info "Config already exists at $config_file"
    fi

    # Crear directorios runtime
    local vault_dir="/var/lib/agentguard/vault"
    local ca_dir="/var/lib/agentguard/ca"
    local log_dir="/var/log/agentguard"
    for d in "$vault_dir" "$ca_dir" "$log_dir"; do
        sudo mkdir -p "$d" 2>/dev/null || mkdir -p "$d"
    done
    sudo chmod 700 "$ca_dir" 2>/dev/null || true

    # Instalar systemd unit
    local unit_file="/etc/systemd/system/agentguard.service"
    if [[ ! -f "$unit_file" ]]; then
        info "Installing systemd service..."
        cat > "$tmp/agentguard.service" <<'UNIEOF'
[Unit]
Description=AgentGuard — kernel-level AI agent protection
Documentation=https://agentguard.io/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agentguard-linux
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_NET_ADMIN CAP_PERFMON

ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/agentguard /var/log/agentguard /etc/agentguard
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictNamespaces=true

LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
UNIEOF
        sudo cp "$tmp/agentguard.service" "$unit_file"
        sudo systemctl daemon-reload
        info "Enabling agentguard.service..."
        sudo systemctl enable --now agentguard 2>/dev/null || {
            warn "Could not enable agentguard.service. Start manually with:"
            warn "  sudo systemctl enable --now agentguard"
        }
        success "systemd unit installed"
    else
        info "systemd unit already exists — skipping"
    fi

    # Añadir CA root al trust store del sistema
    local ca_cert="/var/lib/agentguard/ca/root-cert.pem"
    if [[ -f "$ca_cert" ]]; then
        info "Adding AgentGuard CA to system trust store..."
        if command -v update-ca-trust &>/dev/null; then
            sudo cp "$ca_cert" /etc/pki/ca-trust/source/anchors/agentguard.crt
            sudo update-ca-trust extract
        elif command -v update-ca-certificates &>/dev/null; then
            sudo cp "$ca_cert" /usr/local/share/ca-certificates/agentguard.crt
            sudo update-ca-certificates
        else
            warn "Could not add CA to trust store. Add manually:"
            warn "  cp $ca_cert /usr/local/share/ca-certificates/"
        fi
    fi

    success "AgentGuard installed for Linux!"
    echo ""
    info "Next steps:"
    echo "  1. Edit config:   sudo nano /etc/agentguard/config.toml"
    echo "  2. Check status:   agentguard status"
    echo "  3. Protect a dir:  agentguard protect ~/Documents"
    echo ""
}

# ── Entry point ──────────────────────────────────────────────
main() {
    printf "${BOLD}AgentGuard Installer${NC}\n"
    echo ""

    local os target tmp
    os="$(detect_os)"
    target="$(detect_target)"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    info "Detected: $os ($target)"
    info "Installing version: $VERSION"

    echo ""
    printf "Install AgentGuard for ${BOLD}${os}${NC}? [Y/n] "
    if [[ "${AGENTGUARD_YES:-}" == "1" ]]; then
        echo "Y (auto-confirmed via AGENTGUARD_YES=1)"
    else
        read -r REPLY
        if [[ ! "$REPLY" =~ ^([Yy]|[Yy][Ee][Ss]|)$ ]]; then
            die "Installation cancelled"
        fi
    fi
    echo ""

    case "$os" in
        linux) install_linux "$target" "$tmp" ;;
    esac
}

main "$@"
